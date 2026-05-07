"""SQLite-backed job storage."""
from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime

from ..config import DEFAULT_OUTPUT_DIR

DB_PATH = DEFAULT_OUTPUT_DIR / "jobs.db"
_db_lock = threading.Lock()


def _init() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS jobs (
                job_id TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                created_at TEXT NOT NULL,
                completed_at TEXT,
                status TEXT NOT NULL,
                result_dir TEXT,
                tools_json TEXT NOT NULL,
                base_tool TEXT NOT NULL,
                merge_order_json TEXT NOT NULL,
                custom_sbom_path TEXT,
                error TEXT,
                logs_json TEXT NOT NULL DEFAULT '[]'
            )
        """)
        conn.commit()


@contextmanager
def _connect() -> Generator[sqlite3.Connection]:
    _init()
    with _db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()


def insert_job(job: object) -> None:
    """Insert a freshly created PipelineJob."""
    with _connect() as conn:
        conn.execute(
            """INSERT INTO jobs(job_id, url, created_at, status, tools_json,
               base_tool, merge_order_json, custom_sbom_path, logs_json)
               VALUES(?, ?, ?, 'running', ?, ?, ?, ?, '[]')""",
            (
                job.job_id,  # type: ignore[attr-defined]
                job.url,  # type: ignore[attr-defined]
                datetime.now(UTC).isoformat(timespec="seconds"),
                json.dumps(job.tools),  # type: ignore[attr-defined]
                job.base_tool,  # type: ignore[attr-defined]
                json.dumps(job.merge_order),  # type: ignore[attr-defined]
                job.custom_sbom_path,  # type: ignore[attr-defined]
            ),
        )


def update_job(job: object) -> None:
    """Persist current job state: status, logs, result, error."""
    with _connect() as conn:
        completed = (
            datetime.now(UTC).isoformat(timespec="seconds")
            if getattr(job, "status", None) in ("completed", "failed")
            else None
        )
        conn.execute(
            """UPDATE jobs SET status=?, completed_at=?, result_dir=?, error=?, logs_json=?
               WHERE job_id=?""",
            (
                job.status,  # type: ignore[attr-defined]
                completed,
                job.result_dir,  # type: ignore[attr-defined]
                job.error,  # type: ignore[attr-defined]
                json.dumps(job.logs),  # type: ignore[attr-defined]
                job.job_id,  # type: ignore[attr-defined]
            ),
        )


def get_job_row(job_id: str) -> dict | None:
    """Return a single job row as a plain dict, or None if not found."""
    with _connect() as conn:
        row = conn.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
    return dict(row) if row else None


def list_jobs(limit: int = 100) -> list[dict]:
    """Return up to *limit* jobs ordered by creation time descending."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]
