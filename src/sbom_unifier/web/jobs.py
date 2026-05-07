"""Background pipeline job state, shared across Flask routes."""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from typing import Any

from . import db


@dataclass
class PipelineJob:
    job_id: str
    url: str
    tools: list[str]
    merge_order: list
    base_tool: str
    custom_sbom_path: str | None = None
    status: str = "running"
    logs: list[str] = field(default_factory=list)
    error: str | None = None
    result_dir: str | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def add_log(self, message: str) -> None:
        with self._lock:
            self.logs.append(message)


@dataclass
class _JobView:
    """Read-only view of a job reconstructed from a DB row."""

    job_id: str
    url: str
    tools: list[str]
    merge_order: list[Any]
    base_tool: str
    custom_sbom_path: str | None
    status: str
    logs: list[str]
    error: str | None
    result_dir: str | None
    created_at: str
    completed_at: str | None


def _row_to_view(row: dict) -> _JobView:
    """Convert a DB row dict to a _JobView."""
    return _JobView(
        job_id=row["job_id"],
        url=row["url"],
        tools=json.loads(row["tools_json"]),
        merge_order=json.loads(row["merge_order_json"]),
        base_tool=row["base_tool"],
        custom_sbom_path=row["custom_sbom_path"],
        status=row["status"],
        logs=json.loads(row["logs_json"]),
        error=row["error"],
        result_dir=row["result_dir"],
        created_at=row["created_at"],
        completed_at=row.get("completed_at"),
    )


# Global job registry (thread-safe).
JOBS: dict[str, PipelineJob] = {}
_JOBS_LOCK = threading.Lock()


def register_job(job: PipelineJob) -> None:
    with _JOBS_LOCK:
        JOBS[job.job_id] = job
    db.insert_job(job)


def get_job(job_id: str) -> PipelineJob | None:
    with _JOBS_LOCK:
        return JOBS.get(job_id)


def get_job_or_db(job_id: str) -> PipelineJob | _JobView | None:
    """Return the live PipelineJob if running, otherwise fall back to DB."""
    with _JOBS_LOCK:
        live = JOBS.get(job_id)
    if live is not None:
        return live
    row = db.get_job_row(job_id)
    if row is None:
        return None
    return _row_to_view(row)


