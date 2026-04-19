"""Minimal GitHub REST client for issues, labels, comments and PR lookup."""
from __future__ import annotations

from typing import Any

import httpx

from .logging_config import get_logger

log = get_logger("github")


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

    async def _req(self, method: str, path: str, **kw: Any) -> httpx.Response:
        url = f"{self.base_url}{path}"
        async with httpx.AsyncClient(timeout=self.timeout) as c:
            r = await c.request(method, url, headers=self._headers(), **kw)
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
        r = await self._req("GET", f"/repos/{repo}/labels/{name}")
        if r.status_code == 200:
            return
        await self._req(
            "POST",
            f"/repos/{repo}/labels",
            json={"name": name, "color": color, "description": description},
        )

    # ---------- issues ----------

    async def find_open_issue_by_label(self, repo: str, label: str, marker: str) -> dict | None:
        """Find an open issue tagged with `label` whose body contains `marker`.

        `marker` is typically the dedupe_key appended to the issue body so
        dedupe works even if the label is shared across many findings.
        """
        if self.mock:
            return None
        r = await self._req(
            "GET",
            f"/repos/{repo}/issues",
            params={"state": "open", "labels": label, "per_page": 100},
        )
        if r.status_code != 200:
            return None
        for issue in r.json():
            # GitHub's /issues endpoint returns PRs too; filter them out so we
            # never dedupe a finding against a PR that happens to quote the key.
            if issue.get("pull_request"):
                continue
            body = issue.get("body") or ""
            if marker in body:
                return issue
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
        await self.ensure_label(
            repo,
            "devin-remediation",
            color="b60205",
            description="Tracked by the vulnerability remediation orchestrator",
        )
        r = await self._req(
            "POST",
            f"/repos/{repo}/issues",
            json={"title": title, "body": body, "labels": labels or ["devin-remediation"]},
        )
        r.raise_for_status()
        return r.json()

    async def comment_issue(self, repo: str, number: int, body: str) -> None:
        if self.mock:
            log.info("mock_issue_comment", repo=repo, number=number, body=body[:200])
            return
        r = await self._req(
            "POST", f"/repos/{repo}/issues/{number}/comments", json={"body": body}
        )
        r.raise_for_status()

    async def close_issue(self, repo: str, number: int) -> None:
        if self.mock:
            return
        await self._req(
            "PATCH", f"/repos/{repo}/issues/{number}", json={"state": "closed"}
        )

    # ---------- pulls ----------

    async def find_pr_linked_to_issue(self, repo: str, issue_number: int) -> dict | None:
        """Look for an open PR whose title or body references #issue_number."""
        if self.mock:
            return None
        r = await self._req(
            "GET",
            f"/repos/{repo}/pulls",
            params={"state": "open", "per_page": 100},
        )
        if r.status_code != 200:
            return None
        needle = f"#{issue_number}"
        for pr in r.json():
            if needle in (pr.get("title") or "") or needle in (pr.get("body") or ""):
                return pr
        return None
