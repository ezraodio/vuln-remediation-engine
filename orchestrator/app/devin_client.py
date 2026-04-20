"""Devin v3 API client.

Docs: https://docs.devin.ai/api-reference/overview
Base: https://api.devin.ai/v3/organizations/{org_id}/...

Only the endpoints we actually need:
  - POST   /sessions               (create)
  - GET    /sessions               (list, used for dedupe by tag)
  - GET    /sessions/{id}          (status)
  - POST   /sessions/{id}/message  (feedback into running session)
"""
from __future__ import annotations

from typing import Any, ClassVar

import httpx

from .logging_config import get_logger
from .retry import with_retry

log = get_logger("devin")

_ACU_COST_FIELD_ALIASES = ("acu_cost", "total_acus", "acus_consumed", "acus")
# Session statuses that legitimately have no ACU cost yet (pre-execution).
# Anything else missing all four aliases likely indicates an API rename.
_PRE_EXEC_STATUSES = frozenset({"", "starting", "queued", "pending"})


class DevinClient:
    def __init__(
        self,
        api_key: str,
        org_id: str,
        *,
        base_url: str = "https://api.devin.ai",
        timeout: float = 30.0,
        mock: bool = False,
    ):
        self.api_key = api_key
        self.org_id = org_id
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.mock = mock

    # ---------- internal ----------

    @property
    def _org_url(self) -> str:
        return f"{self.base_url}/v3/organizations/{self.org_id}"

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    async def _request(
        self, method: str, path: str, *, retry: bool = False, **kw: Any
    ) -> httpx.Response:
        """Issue a request; optionally retry on transient failures.

        Set ``retry=True`` for idempotent calls (GETs, or POSTs the API
        guarantees to dedupe server-side). Non-idempotent POSTs leave it
        False so a partial network failure doesn't silently duplicate state.
        """
        url = f"{self._org_url}{path}"

        async def _once() -> httpx.Response:
            async with httpx.AsyncClient(timeout=self.timeout) as c:
                return await c.request(method, url, headers=self._headers(), **kw)

        if retry:
            r = await with_retry(_once, op=f"devin:{method} {path}")
        else:
            r = await _once()
        if r.status_code >= 400:
            log.warning(
                "devin_api_error",
                method=method,
                path=path,
                status=r.status_code,
                body=r.text[:500],
            )
        return r

    # ---------- public ----------

    async def create_session(
        self,
        *,
        prompt: str,
        title: str | None = None,
        tags: list[str] | None = None,
        idempotent: bool = True,
    ) -> dict:
        """Create a new Devin session.

        Returns {"session_id": "...", "url": "..."} on success.
        """
        if self.mock:
            fake_id = f"mock-{hash(prompt) & 0xFFFFFFFF:x}"
            return {
                "session_id": fake_id,
                "url": f"https://app.devin.ai/sessions/{fake_id}",
                "is_new_session": True,
                "mock": True,
            }
        body: dict[str, Any] = {"prompt": prompt, "idempotent": idempotent}
        if title:
            body["title"] = title
        if tags:
            body["tags"] = tags[:50]
        # create_session with idempotent=True is safe to retry: Devin
        # deduplicates server-side on a hash of the prompt+tags+user.
        r = await self._request(
            "POST", "/sessions", json=body, retry=bool(idempotent)
        )
        r.raise_for_status()
        return r.json()

    async def get_session(self, session_id: str) -> dict:
        if self.mock:
            return {"session_id": session_id, "status": "running", "pull_requests": []}
        r = await self._request("GET", f"/sessions/{session_id}", retry=True)
        r.raise_for_status()
        return r.json()

    async def list_sessions_by_tag(
        self, tag: str, *, page_size: int = 50, max_pages: int = 10
    ) -> list[dict]:
        """Find sessions whose tags include `tag`. Used for dedupe.

        Pages through results so busy orgs don't silently drop matches off the
        tail. `max_pages` bounds latency and is a sane cap for dedupe lookups.

        Follows ``next_cursor`` only — never the request's own ``cursor``
        field, which some paginated APIs echo back verbatim and would
        otherwise drive us in a loop requesting the same page. Matches are
        de-duplicated by session_id as a belt-and-suspenders guard against
        pagination bugs upstream.
        """
        if self.mock:
            return []
        matches: list[dict] = []
        seen: set[str] = set()
        cursor: str | None = None
        for _ in range(max_pages):
            path = f"/sessions?limit={page_size}"
            if cursor:
                path += f"&cursor={cursor}"
            r = await self._request("GET", path, retry=True)
            if r.status_code != 200:
                break
            body = r.json()
            items = body.get("items", [])
            for s in items:
                sid = s.get("session_id") or s.get("id")
                if sid is not None:
                    if sid in seen:
                        continue
                    seen.add(sid)
                if tag in (s.get("tags") or []):
                    matches.append(s)
            next_cursor = body.get("next_cursor")
            if not next_cursor or not items:
                break
            cursor = next_cursor
        return matches

    async def send_message(self, session_id: str, message: str) -> None:
        """Post a message into a running session (used for verification feedback)."""
        if self.mock:
            log.info("mock_devin_send_message", session_id=session_id, message=message[:200])
            return
        # send_message is best-effort feedback to a running session; a
        # duplicate message on retry is harmless (Devin sees it twice at
        # worst).
        r = await self._request(
            "POST",
            f"/sessions/{session_id}/message",
            json={"message": message},
            retry=True,
        )
        r.raise_for_status()

    def session_is_active(self, session: dict) -> bool:
        """Is the session still doing work? (as opposed to finished/stopped)"""
        status = (session.get("status") or "").lower()
        if session.get("is_archived"):
            return False
        return status in {"running", "starting", "queued", "pending", "working"}

    # Process-wide set of session_ids we've already logged a "no ACU field"
    # warning for. Cost dashboards silently zeroing out is exactly the class
    # of failure the alias list exists to guard against; if all aliases miss
    # we want one (and only one) log line per session to surface the drift.
    _warned_acu_missing: ClassVar[set[str]] = set()

    @staticmethod
    def session_acu_cost(session: dict) -> float | None:
        """Extract ACU spend from a session payload, tolerating field drift.

        The v3 API has surfaced the cost field under a handful of names across
        releases (acu_cost, total_acus, acus_consumed). Check each so a rename
        upstream doesn't silently zero out our cost dashboard. When all of
        them are missing on an already-running session, emit a single warning
        per session_id so we notice the drift rather than silently reporting
        zero.
        """
        for key in _ACU_COST_FIELD_ALIASES:
            v = session.get(key)
            if v is None:
                continue
            try:
                return float(v)
            except (TypeError, ValueError):
                continue
        DevinClient._maybe_warn_acu_missing(session)
        return None

    @staticmethod
    def _maybe_warn_acu_missing(session: dict) -> None:
        sid = session.get("session_id") or session.get("id")
        if not sid or sid in DevinClient._warned_acu_missing:
            return
        status = (session.get("status") or "").lower()
        if status in _PRE_EXEC_STATUSES:
            return
        log.warning(
            "acu_cost_field_missing",
            session_id=sid,
            status=status,
            known_fields=sorted(session.keys()),
        )
        DevinClient._warned_acu_missing.add(sid)
