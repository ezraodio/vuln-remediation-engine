"""SQLite store for remediation records and events.

Kept tiny and schema-manual on purpose — no ORM dependency.
"""
from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from .models import Finding, RemediationRecord, RemediationStatus

_SCHEMA = """
CREATE TABLE IF NOT EXISTS remediations (
    dedupe_key TEXT PRIMARY KEY,
    finding_json TEXT NOT NULL,
    status TEXT NOT NULL,
    issue_number INTEGER,
    issue_url TEXT,
    session_id TEXT,
    session_url TEXT,
    pr_url TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    resolved_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_remediations_status ON remediations(status);
CREATE INDEX IF NOT EXISTS idx_remediations_session ON remediations(session_id);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dedupe_key TEXT NOT NULL,
    kind TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_key ON events(dedupe_key);
"""


class Store:
    """Thin synchronous SQLite wrapper.

    FastAPI runs this via threads; SQLite's own locking is fine at the
    throughput we expect. Each method opens a short-lived connection.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.executescript(_SCHEMA)

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, isolation_level=None, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        try:
            yield conn
        finally:
            conn.close()

    # ---------- remediations ----------

    def get(self, dedupe_key: str) -> RemediationRecord | None:
        with self._conn() as c:
            row = c.execute(
                "SELECT * FROM remediations WHERE dedupe_key = ?", (dedupe_key,)
            ).fetchone()
        return _row_to_record(row) if row else None

    def upsert(self, record: RemediationRecord) -> None:
        with self._conn() as c:
            c.execute(
                """
                INSERT INTO remediations (
                    dedupe_key, finding_json, status, issue_number, issue_url,
                    session_id, session_url, pr_url,
                    created_at, updated_at, resolved_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(dedupe_key) DO UPDATE SET
                    finding_json=excluded.finding_json,
                    status=excluded.status,
                    issue_number=COALESCE(excluded.issue_number, remediations.issue_number),
                    issue_url=COALESCE(excluded.issue_url, remediations.issue_url),
                    session_id=COALESCE(excluded.session_id, remediations.session_id),
                    session_url=COALESCE(excluded.session_url, remediations.session_url),
                    pr_url=COALESCE(excluded.pr_url, remediations.pr_url),
                    updated_at=excluded.updated_at,
                    resolved_at=COALESCE(excluded.resolved_at, remediations.resolved_at)
                """,
                (
                    record.dedupe_key,
                    record.finding.model_dump_json(),
                    record.status.value,
                    record.issue_number,
                    record.issue_url,
                    record.session_id,
                    record.session_url,
                    record.pr_url,
                    record.created_at.isoformat(),
                    record.updated_at.isoformat(),
                    record.resolved_at.isoformat() if record.resolved_at else None,
                ),
            )

    def list_all(self) -> list[RemediationRecord]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT * FROM remediations ORDER BY created_at DESC"
            ).fetchall()
        return [_row_to_record(r) for r in rows]

    def update_status(
        self,
        dedupe_key: str,
        status: RemediationStatus,
        *,
        issue_number: int | None = None,
        issue_url: str | None = None,
        session_id: str | None = None,
        session_url: str | None = None,
        pr_url: str | None = None,
        mark_resolved: bool = False,
    ) -> RemediationRecord | None:
        rec = self.get(dedupe_key)
        if not rec:
            return None
        rec.status = status
        if issue_number is not None:
            rec.issue_number = issue_number
        if issue_url is not None:
            rec.issue_url = issue_url
        if session_id is not None:
            rec.session_id = session_id
        if session_url is not None:
            rec.session_url = session_url
        if pr_url is not None:
            rec.pr_url = pr_url
        now = datetime.utcnow()
        rec.updated_at = now
        if mark_resolved:
            rec.resolved_at = now
        self.upsert(rec)
        return rec

    # ---------- events ----------

    def log_event(self, dedupe_key: str, kind: str, payload: dict) -> None:
        with self._conn() as c:
            c.execute(
                "INSERT INTO events (dedupe_key, kind, payload_json, created_at) VALUES (?, ?, ?, ?)",
                (dedupe_key, kind, json.dumps(payload), datetime.utcnow().isoformat()),
            )

    def recent_events(self, limit: int = 50) -> list[dict]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [
            {
                "id": r["id"],
                "dedupe_key": r["dedupe_key"],
                "kind": r["kind"],
                "payload": json.loads(r["payload_json"]),
                "created_at": r["created_at"],
            }
            for r in rows
        ]


def _row_to_record(row: sqlite3.Row) -> RemediationRecord:
    finding_data = json.loads(row["finding_json"])
    return RemediationRecord(
        dedupe_key=row["dedupe_key"],
        finding=Finding.model_validate(finding_data),
        status=RemediationStatus(row["status"]),
        issue_number=row["issue_number"],
        issue_url=row["issue_url"],
        session_id=row["session_id"],
        session_url=row["session_url"],
        pr_url=row["pr_url"],
        created_at=datetime.fromisoformat(row["created_at"]),
        updated_at=datetime.fromisoformat(row["updated_at"]),
        resolved_at=datetime.fromisoformat(row["resolved_at"]) if row["resolved_at"] else None,
    )
