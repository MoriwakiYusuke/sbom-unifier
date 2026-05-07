"""Flask Web UI for sbom-unifier."""

from __future__ import annotations

import contextlib
import csv
import io
import json
import os
import shutil
import threading
import uuid
from pathlib import Path

from dotenv import load_dotenv, set_key
from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

from ..clone import parse_github_url
from ..config import DEFAULT_OUTPUT_DIR, UNIFIED_SBOM_FILENAME, get_project_paths
from ..pipeline import run_pipeline
from ..tools import REGISTRY
from . import db
from .jobs import PipelineJob, get_job_or_db, register_job

ENV_PATH = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(ENV_PATH)

app = Flask(__name__)
app.secret_key = os.urandom(24)


def _capture_pipeline(job: PipelineJob) -> None:
    """Run the pipeline with stdout/stderr captured into the job log."""

    class LogCapture(io.StringIO):
        def __init__(self, job: PipelineJob):
            super().__init__()
            self._job = job

        def write(self, s: str) -> int:
            if s.strip():
                self._job.add_log(s.rstrip())
            return super().write(s)

        def flush(self) -> None:
            return None

    capture = LogCapture(job)
    try:
        with contextlib.redirect_stdout(capture), contextlib.redirect_stderr(capture):
            success = run_pipeline(
                url=job.url,
                enabled_tools=job.tools,
                base_tool=job.base_tool,
                merge_order=job.merge_order,
                custom_sbom_path=job.custom_sbom_path,
                output_root=None,
            )
        if success:
            job.status = "completed"
            parsed = parse_github_url(job.url)
            if parsed:
                _, repo_name = parsed
                job.result_dir = str(get_project_paths(repo_name)["project_dir"])
        else:
            job.status = "failed"
            job.error = "Pipeline execution failed"
    except Exception as exc:
        job.status = "failed"
        job.error = str(exc)
        job.add_log(f"Error: {exc}")
    finally:
        db.update_job(job)
        if job.custom_sbom_path:
            with contextlib.suppress(OSError):
                Path(job.custom_sbom_path).unlink(missing_ok=True)


@app.route("/")
def index():
    by_position = lambda t: t.default_merge_position  # noqa: E731
    return render_template(
        "index.html",
        github_token=os.environ.get("GITHUB_TOKEN", ""),
        generators=sorted(REGISTRY.generators(), key=by_position),
        base_candidates=sorted(REGISTRY.base_candidates(), key=by_position),
        merge_order=REGISTRY.default_merge_order(),
        base_tool_default=min(REGISTRY.base_candidates(), key=by_position).name,
    )


@app.route("/settings/token", methods=["POST"])
def save_token():
    token = request.form.get("github_token", "").strip()
    os.environ["GITHUB_TOKEN"] = token
    ENV_PATH.parent.mkdir(parents=True, exist_ok=True)
    set_key(str(ENV_PATH), "GITHUB_TOKEN", token)
    flash("GITHUB_TOKEN saved.", "success")
    return redirect(url_for("index"))


@app.route("/run", methods=["POST"])
def run_route():
    url = request.form.get("url", "").strip()
    if not url:
        flash("Please enter a GitHub repository URL.", "error")
        return redirect(url_for("index"))

    valid_generator_names = {t.name for t in REGISTRY.generators()}
    tools = [t for t in request.form.getlist("tools") if t in valid_generator_names]
    if not tools:
        tools = sorted(valid_generator_names)

    valid_base_tools = {t.name for t in REGISTRY.base_candidates()}
    base_tool = request.form.get("base_tool", "").strip()
    if base_tool not in valid_base_tools:
        base_tool = min(
            REGISTRY.base_candidates(),
            key=lambda t: t.default_merge_position,
        ).name

    raw_order = request.form.get("merge_order", "")
    if raw_order:
        try:
            parsed_order = json.loads(raw_order)
            order = [item[0] if isinstance(item, list) else str(item) for item in parsed_order]
        except (json.JSONDecodeError, IndexError, TypeError):
            order = [t.name for t in REGISTRY.default_merge_order()]
    else:
        order = [t.name for t in REGISTRY.default_merge_order()]

    job_id = str(uuid.uuid4())[:8]

    custom_sbom_path: str | None = None
    uploaded = request.files.get("custom_sbom")
    if uploaded and uploaded.filename:
        try:
            content = uploaded.read()
            json.loads(content)
        except (json.JSONDecodeError, UnicodeDecodeError):
            flash("Custom SBOM must be valid JSON.", "error")
            return redirect(url_for("index"))
        upload_dir = DEFAULT_OUTPUT_DIR / "_uploads"
        upload_dir.mkdir(parents=True, exist_ok=True)
        temp = upload_dir / f"{job_id}_custom-sbom.json"
        temp.write_bytes(content)
        custom_sbom_path = str(temp)
        flash("Custom SBOM will be applied to this run only.", "info")

    job = PipelineJob(
        job_id=job_id,
        url=url,
        tools=tools,
        merge_order=order,
        base_tool=base_tool,
        custom_sbom_path=custom_sbom_path,
    )
    register_job(job)

    threading.Thread(target=_capture_pipeline, args=(job,), daemon=True).start()
    return redirect(url_for("job_status", job_id=job_id))


@app.route("/job/<job_id>")
def job_status(job_id: str):
    job = get_job_or_db(job_id)
    if not job:
        flash("Job not found.", "error")
        return redirect(url_for("index"))
    return render_template("job.html", job=job)


@app.route("/api/job/<job_id>")
def api_job_status(job_id: str):
    job = get_job_or_db(job_id)
    if not job:
        return jsonify({"error": "not found"}), 404
    return jsonify(
        {
            "status": job.status,
            "logs": job.logs,
            "error": job.error,
            "result_dir": job.result_dir,
        }
    )


@app.route("/download/<job_id>")
def download_sbom(job_id: str):
    job = get_job_or_db(job_id)
    if not job or not job.result_dir:
        flash("No SBOM available to download.", "error")
        return redirect(url_for("index"))
    path = Path(job.result_dir) / UNIFIED_SBOM_FILENAME
    if not path.exists():
        flash(f"{UNIFIED_SBOM_FILENAME} not found.", "error")
        return redirect(url_for("job_status", job_id=job_id))
    return send_file(
        path,
        as_attachment=True,
        download_name=UNIFIED_SBOM_FILENAME,
        mimetype="application/json",
    )


@app.route("/download_all/<job_id>")
def download_all(job_id: str):
    job = get_job_or_db(job_id)
    if not job or not job.result_dir:
        flash("No files available to download.", "error")
        return redirect(url_for("index"))
    result_dir = Path(job.result_dir)
    if not result_dir.exists():
        flash("Result directory not found.", "error")
        return redirect(url_for("job_status", job_id=job_id))
    zip_base = result_dir.parent / f"{result_dir.name}_results"
    shutil.make_archive(str(zip_base), "zip", str(result_dir))
    return send_file(
        f"{zip_base}.zip",
        as_attachment=True,
        download_name=f"{result_dir.name}_results.zip",
        mimetype="application/zip",
    )


@app.route("/jobs")
def jobs_list():
    """List all past jobs from the database (persists across restarts)."""
    from .jobs import _row_to_view

    rows = db.list_jobs()
    all_jobs = [_row_to_view(r) for r in rows]
    return render_template("jobs.html", all_jobs=all_jobs)


@app.route("/job/<job_id>/statistics")
def job_statistics(job_id: str):
    job = get_job_or_db(job_id)
    if not job or not job.result_dir:
        flash("No analysis results.", "error")
        return redirect(url_for("index"))
    analysis_dir = Path(job.result_dir) / "analysis"
    comparison, meta_cols, tool_cols, summary = _load_job_analysis(analysis_dir)
    return render_template(
        "job_statistics.html",
        job=job,
        comparison_data=comparison,
        meta_cols=meta_cols,
        tool_cols=tool_cols,
        summary=summary,
    )


_META_COLS = ("Category", "SPDX Field", "Attribute", "カテゴリ", "SPDX項目", "属性")


def _load_job_analysis(analysis_dir: Path):
    """Load SPDX comparison + percentage CSVs and merge into one row list.

    Each tool cell becomes {"status": "<full|part|miss|...>", "percent": "<NN.N%>"}
    so the template can render status and ratio side-by-side without a second table.
    """
    comparison: list[dict] = []
    percent: list[dict] = []
    if analysis_dir.exists():
        for f in sorted(analysis_dir.iterdir()):
            if f.suffix != ".csv":
                continue
            if f.name.endswith("_spdx_comparison_percent.csv"):
                percent = _read_csv(f)
            elif f.name.endswith("_spdx_comparison.csv"):
                comparison = _read_csv(f)

    if not comparison:
        return [], [], [], {}

    meta_cols = [k for k in comparison[0].keys() if k in _META_COLS]
    tool_cols = [k for k in comparison[0].keys() if k not in _META_COLS]

    percent_by_field = {(r.get("Category"), r.get("SPDX Field")): r for r in percent}

    merged: list[dict] = []
    for row in comparison:
        out = {col: row.get(col, "") for col in meta_cols}
        pct_row = percent_by_field.get((row.get("Category"), row.get("SPDX Field")), {})
        for tool in tool_cols:
            out[tool] = {
                "status": row.get(tool, "").strip(),
                "percent": pct_row.get(tool, "").strip(),
            }
        merged.append(out)

    tool_stats = {}
    for tool in tool_cols:
        counts = {"full": 0, "part": 0, "miss": 0, "other": 0}
        for row in comparison:
            val = row.get(tool, "").strip().lower()
            if val in ("〇", "full"):
                counts["full"] += 1
            elif val in ("△", "part"):
                counts["part"] += 1
            elif val in ("×", "miss", "no", "noassertion"):
                counts["miss"] += 1
            else:
                counts["other"] += 1
        total = sum(counts.values())
        if total > 0:
            tool_stats[tool] = {
                **counts,
                "total": total,
                "full_pct": round(counts["full"] / total * 100, 1),
                "part_pct": round(counts["part"] / total * 100, 1),
                "miss_pct": round(counts["miss"] / total * 100, 1),
            }

    return merged, meta_cols, tool_cols, {"tools": tool_stats}


def _read_csv(path: Path):
    rows: list[dict] = []
    with open(path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            rows.append(dict(row))
    return rows


def run() -> None:
    """Console-script entrypoint for `sbom-unifier-web`."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="sbom-unifier-web",
        description="Start the sbom-unifier Flask Web UI.",
    )
    parser.add_argument("--host", default="127.0.0.1",
                        help="Bind address (default: 127.0.0.1).")
    parser.add_argument("--port", type=int, default=5000,
                        help="Port (default: 5000).")
    parser.add_argument("--debug", action="store_true",
                        help="Enable Flask debug mode.")
    args = parser.parse_args()
    app.run(host=args.host, port=args.port, debug=args.debug)
