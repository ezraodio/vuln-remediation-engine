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

from typing import Any

import httpx

from .logging_config import get_logger
from .retry import with_retry

log = get_logger("devin")


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
        max_acu_limit: int | None = None,
        create_as_user_id: str | None = None,
        playbook_id: str | None = None,
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
        if max_acu_limit:
            body["max_acu_limit"] = max_acu_limit
        if create_as_user_id:
            body["create_as_user_id"] = create_as_user_id
        if playbook_id:
            body["playbook_id"] = playbook_id
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
        """
        if self.mock:
            return []
        matches: list[dict] = []
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
            matches.extend(s for s in items if tag in (s.get("tags") or []))
            cursor = body.get("next_cursor") or body.get("cursor") or None
            if not cursor or not items:
                break
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
