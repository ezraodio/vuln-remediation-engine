"""Minimal GitHub REST client for issues, labels, comments and PR lookup."""
from __future__ import annotations

import re
from typing import Any

import httpx

from .logging_config import get_logger
from .retry import with_retry

log = get_logger("github")

_PR_URL_RE = re.compile(
    r"https?://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/pull/(?P<number>\d+)"
)


class GitHubClient:
    def __init__(
        self,
        token: str,
        *,
        base_url: str = "https://api.github.com",
        timeout: float = 30.0,
        mock: bool = False,
    ):
        self.token = token
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.mock = mock

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    async def _request(
        self, method: str, path: str, *, retry: bool = False, **kw: Any
    ) -> httpx.Response:
        """Issue a GitHub request; opt-in retry for idempotent calls only.

        We DO NOT retry POST /issues or POST /comments: if the first request
        actually reached GitHub but the response was lost in transit, a
        retry would duplicate the resource. GETs and PATCHes (e.g. close
        issue) are safe.
        """
        url = f"{self.base_url}{path}"

        async def _once() -> httpx.Response:
            async with httpx.AsyncClient(timeout=self.timeout) as c:
                return await c.request(method, url, headers=self._headers(), **kw)

        if retry:
            r = await with_retry(_once, op=f"gh:{method} {path}")
        else:
            r = await _once()
        if r.status_code >= 400:
            log.warning(
                "github_api_error",
                method=method,
                path=path,
                status=r.status_code,
                body=r.text[:500],
            )
        return r

    # ---------- labels ----------

    async def ensure_label(self, repo: str, name: str, color: str = "b60205", description: str = "") -> None:
        if self.mock:
            return
        r = await self._request("GET", f"/repos/{repo}/labels/{name}", retry=True)
        if r.status_code == 200:
            return
        await self._request(
            "POST",
            f"/repos/{repo}/labels",
            json={"name": name, "color": color, "description": description},
        )

    # ---------- issues ----------

    async def find_open_issue_by_label(
        self,
        repo: str,
        label: str,
        marker: str,
        *,
        max_pages: int = 10,
    ) -> dict | None:
        """Find an open issue tagged with `label` whose body contains `marker`.

        `marker` is typically the dedupe_key appended to the issue body so
        dedupe works even if the label is shared across many findings.

        Pages through results: a long-running target repo can accumulate
        more than one page of open issues under the same label, and we must
        not silently drop matches off the tail (would let duplicate issues
        slip through the dedupe layer).
        """
        if self.mock:
            return None
        for page in range(1, max_pages + 1):
            r = await self._request(
                "GET",
                f"/repos/{repo}/issues",
                params={
                    "state": "open",
                    "labels": label,
                    "per_page": 100,
                    "page": page,
                },
                retry=True,
            )
            if r.status_code != 200:
                return None
            batch = r.json()
            if not batch:
                return None
            for issue in batch:
                # GitHub's /issues endpoint returns PRs too; filter them out
                # so we never dedupe a finding against a PR that quotes the key.
                if issue.get("pull_request"):
                    continue
                body = issue.get("body") or ""
                if marker in body:
                    return issue
            if len(batch) < 100:
                return None
        return None

    async def create_issue(
        self,
        repo: str,
        *,
        title: str,
        body: str,
        labels: list[str] | None = None,
    ) -> dict:
        if self.mock:
            return {
                "number": 0,
                "html_url": f"https://github.com/{repo}/issues/mock",
                "mock": True,
            }
        applied_labels = labels or ["devin-remediation"]
        # Ensure the caller's primary (orchestrator) label exists with a
        # description/colour so operators filtering the Issues tab get useful
        # metadata. GitHub will auto-create any label that doesn't exist when
        # the issue is filed, but those auto-created labels have no colour or
        # description — worth the one extra request to make the label useful.
        await self.ensure_label(
            repo,
            applied_labels[0],
            color="b60205",
            description="Tracked by the vulnerability remediation orchestrator",
        )
        r = await self._request(
            "POST",
            f"/repos/{repo}/issues",
            json={"title": title, "body": body, "labels": applied_labels},
        )
        r.raise_for_status()
        return r.json()

    async def comment_issue(self, repo: str, number: int, body: str) -> None:
        if self.mock:
            log.info("mock_issue_comment", repo=repo, number=number, body=body[:200])
            return
        r = await self._request(
            "POST", f"/repos/{repo}/issues/{number}/comments", json={"body": body}
        )
        r.raise_for_status()

    async def close_issue(
        self, repo: str, number: int, *, reason: str = "completed"
    ) -> None:
        """Close a tracking issue once the underlying finding is resolved.

        PATCH is idempotent so retrying on a lost response is safe — replay
        against an already-closed issue is a 200 no-op with the same body.
        `reason="completed"` tells GitHub to render the green "Closed as
        completed" marker, distinguishing it from "not planned" closures.
        """
        if self.mock:
            log.info("mock_issue_close", repo=repo, number=number, reason=reason)
            return
        r = await self._request(
            "PATCH",
            f"/repos/{repo}/issues/{number}",
            json={"state": "closed", "state_reason": reason},
            retry=True,
        )
        r.raise_for_status()

    # ---------- pulls ----------

    async def get_pr_state(self, pr_url: str) -> dict | None:
        """Fetch a PR's state given its html_url.

        Returns ``{"state": "open"|"closed", "merged": bool}`` or ``None`` if
        the URL isn't parseable or the fetch fails. Used by the stale-PR
        reconciler to decide whether a long-open PR was merged, rejected, or
        is still genuinely pending review.
        """
        if self.mock:
            return None
        m = _PR_URL_RE.match(pr_url or "")
        if not m:
            return None
        owner, repo, number = m.group("owner"), m.group("repo"), m.group("number")
        r = await self._request(
            "GET", f"/repos/{owner}/{repo}/pulls/{number}", retry=True
        )
        if r.status_code != 200:
            return None
        body = r.json()
        return {
            "state": body.get("state"),
            "merged": bool(body.get("merged")),
        }
