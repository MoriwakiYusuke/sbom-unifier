"""Tests for Flask app and job state."""

import os
import threading
from unittest.mock import patch

import pytest

from sbom_unifier.web.app import app
from sbom_unifier.web.jobs import JOBS, PipelineJob, register_job


def test_pipeline_job_records_logs_thread_safely():
    job = PipelineJob(
        job_id="abc",
        url="x",
        tools=["syft"],
        merge_order=["syft"],
        base_tool="syft",
        custom_sbom_path=None,
    )
    threads = [threading.Thread(target=job.add_log, args=(f"line-{i}",)) for i in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(job.logs) == 50


def test_register_job_stores_job_in_jobs_dict():
    job = PipelineJob(
        job_id="def",
        url="x",
        tools=[],
        merge_order=[],
        base_tool="syft",
        custom_sbom_path=None,
    )
    with patch("sbom_unifier.web.jobs.db.insert_job"):
        register_job(job)
    assert JOBS["def"] is job


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with (
        patch("sbom_unifier.web.jobs.db.insert_job"),
        patch("sbom_unifier.web.jobs.db.get_job_row", return_value=None),
        patch("sbom_unifier.web.jobs.db.list_jobs", return_value=[]),
        patch("sbom_unifier.web.app.db.update_job"),
        app.test_client() as c,
    ):
        yield c


def test_run_without_url_redirects_with_error(client):
    rv = client.post("/run", data={})
    assert rv.status_code == 302  # redirect back to index


def test_api_job_status_404_for_unknown_id(client):
    rv = client.get("/api/job/doesnotexist")
    assert rv.status_code == 404


def test_download_unknown_job_redirects(client):
    rv = client.get("/download/doesnotexist")
    assert rv.status_code == 302


def test_save_token_persists_to_environ(client):
    rv = client.post("/settings/token", data={"github_token": "ghp_test"})
    assert rv.status_code == 302
    assert os.environ["GITHUB_TOKEN"] == "ghp_test"


def test_index_renders(client):
    rv = client.get("/")
    assert rv.status_code == 200
    body = rv.data.lower()
    # English title or branding visible
    assert b"sbom" in body
