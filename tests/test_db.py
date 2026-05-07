"""Tests for SQLite-backed job storage."""

from __future__ import annotations

from pathlib import Path

import pytest

import sbom_unifier.web.db as db_module
from sbom_unifier.web.jobs import PipelineJob


@pytest.fixture
def isolated_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Redirect DB_PATH to a temporary file for each test."""
    test_db = tmp_path / "test_jobs.db"
    monkeypatch.setattr(db_module, "DB_PATH", test_db)
    yield test_db


def _make_job(job_id: str = "test-01", url: str = "https://github.com/test/repo") -> PipelineJob:
    return PipelineJob(
        job_id=job_id,
        url=url,
        tools=["syft", "trivy"],
        merge_order=["sbom-tool", "syft", "trivy"],
        base_tool="sbom-tool",
        custom_sbom_path=None,
    )


def test_insert_then_get_returns_same_fields(isolated_db):
    job = _make_job()
    db_module.insert_job(job)

    row = db_module.get_job_row(job.job_id)
    assert row is not None
    assert row["job_id"] == job.job_id
    assert row["url"] == job.url
    assert row["base_tool"] == job.base_tool
    assert row["status"] == "running"
    assert row["result_dir"] is None
    assert row["error"] is None


def test_update_changes_status_and_completed_at(isolated_db):
    job = _make_job()
    db_module.insert_job(job)

    job.status = "completed"
    job.result_dir = "/some/output/repo"
    db_module.update_job(job)

    row = db_module.get_job_row(job.job_id)
    assert row is not None
    assert row["status"] == "completed"
    assert row["result_dir"] == "/some/output/repo"
    assert row["completed_at"] is not None


def test_update_failed_status(isolated_db):
    job = _make_job()
    db_module.insert_job(job)

    job.status = "failed"
    job.error = "Something went wrong"
    db_module.update_job(job)

    row = db_module.get_job_row(job.job_id)
    assert row is not None
    assert row["status"] == "failed"
    assert row["error"] == "Something went wrong"
    assert row["completed_at"] is not None


def test_list_orders_by_created_desc(isolated_db, monkeypatch: pytest.MonkeyPatch):
    """Insert three jobs with distinct timestamps and verify descending order."""
    from datetime import datetime

    timestamps = [
        "2025-01-01T00:00:01+00:00",
        "2025-01-01T00:00:02+00:00",
        "2025-01-01T00:00:03+00:00",
    ]
    call_count = 0

    def fake_now(tz=None):
        nonlocal call_count
        ts = datetime.fromisoformat(timestamps[min(call_count, len(timestamps) - 1)])
        call_count += 1
        return ts

    import sbom_unifier.web.db as db_mod
    monkeypatch.setattr(db_mod, "datetime", type("FakeDatetime", (), {
        "now": staticmethod(fake_now),
    }))

    job_a = _make_job(job_id="aaa", url="https://github.com/test/a")
    job_b = _make_job(job_id="bbb", url="https://github.com/test/b")
    job_c = _make_job(job_id="ccc", url="https://github.com/test/c")

    db_module.insert_job(job_a)
    db_module.insert_job(job_b)
    db_module.insert_job(job_c)

    rows = db_module.list_jobs()
    assert len(rows) == 3
    ids = [r["job_id"] for r in rows]
    assert set(ids) == {"aaa", "bbb", "ccc"}
    # Newest (ccc, timestamp index 2) should be first.
    assert rows[0]["job_id"] == "ccc"


def test_get_job_row_returns_none_for_missing(isolated_db):
    result = db_module.get_job_row("nonexistent")
    assert result is None
