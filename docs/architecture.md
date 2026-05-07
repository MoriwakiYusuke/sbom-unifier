# Architecture Overview

A map for developers getting acquainted with the codebase. For day-to-day commands, see [development.md](development.md).

## Pipeline flow

Both the CLI and the Web UI ultimately call `pipeline.run_pipeline()`. The flow lives in [pipeline.py](../src/sbom_unifier/pipeline.py).

```
GitHub URL
    │
    ▼
┌─────────────────────────┐
│ 1. clone (clone.py)     │  git clone --depth 1, then strip .git
└─────────────────────────┘
    │
    ▼
┌─────────────────────────┐
│ 2. generate (tools/*)   │  iterate REGISTRY.generators()
│   - sbom-tool           │  each tool's generate(repo_path, output_dir, ...)
│   - syft                │  → writes <tool>-sbom.json under output_dir
│   - trivy               │
│   - github              │  (custom: separately drop a user upload into output_dir)
└─────────────────────────┘
    │
    ▼
┌─────────────────────────┐
│ 3. resolve base         │  --base-tool, or smallest default_merge_position
└─────────────────────────┘  (fall back to any existing file if missing)
    │
    ▼
┌─────────────────────────┐
│ 4. merge (merge/*)      │  for each tool: merge_sbom(base, src, tool)
│                         │   - PURL-based package dedup
│                         │   - field-by-field backfill (merge/fields.py)
│                         │   - transitive dependency injection
└─────────────────────────┘
    │
    ▼
┌─────────────────────────┐
│ 5. enrich (enrichment/) │  file_types: derive SPDX fileTypes from extensions
│                         │  ninka: backfill license/copyright via the Perl tool
└─────────────────────────┘
    │
    ▼
┌─────────────────────────┐
│ 6. save                 │  unified_sbom.json
│                         │  (config.UNIFIED_SBOM_FILENAME)
└─────────────────────────┘
    │
    ▼
┌─────────────────────────┐
│ 7. analyze (analyze/*)  │  per-tool coverage of SPDX 80 fields → CSV
└─────────────────────────┘  → analysis/<repo>_spdx_comparison.csv
```

Every step is **designed to keep going on failure** (e.g., base falls back to any existing file; analyze is best-effort try/except). The bias is "produce a usable SBOM whenever possible" — this is offline analysis support, not a strict validator.

## Tool registry design

`ToolRegistry` in `src/sbom_unifier/tools/registry.py` is the single source of truth for every generator.

- Each tool calls `REGISTRY.register(ToolEntry(...))` from inside `tools/<name>.py`
- A one-line `from . import <name>` in the `# === ADD NEW TOOL HERE ===` block of `tools/__init__.py` triggers registration via import side effect
- `pipeline.py`, `cli.py`, and `web/app.py` all enumerate generators via `REGISTRY` — adding a new tool does not require touching any of them

For `ToolEntry` fields and the new-tool procedure, see [adding-tools.md](adding-tools.md).

`pipeline.py:_resolve_generate()` re-imports the module via `importlib.import_module(f"sbom_unifier.tools.{name}")` and looks up `generate` fresh each call. The reason: **so tests can `monkeypatch` `sbom_unifier.tools.syft.generate`** and have it take effect. If we held on to the callable that the registry was given at registration time, the patch would not stick.

## Output path resolution (important)

`config.py`:

```python
PACKAGE_DIR = Path(__file__).resolve().parent
DEFAULT_OUTPUT_DIR = PACKAGE_DIR / "output"
```

So the Web UI's output directory is locked to **`output/` directly under the installed package directory**. The CLI can override with `--output`; the Web UI has no override.

This caused the Docker trap, which is why we use **editable install (`pip install -e .`) + symlink**:

- A non-editable install (`pip install .`) puts `__file__` under site-packages, which makes `-v ./output:/app/output` a no-op
- An editable install keeps `__file__` at `/app/src/sbom_unifier/config.py`, and a symlink `/app/src/sbom_unifier/output → /app/output` redirects writes through to the bind mount target (see Dockerfile)

**Heads-up for new contributors:** changing how `DEFAULT_OUTPUT_DIR` is resolved in `config.py` will conflict with the Docker symlink setup. If you change it, also revisit the Dockerfile's `RUN mkdir -p /app/output && ln -sfn ...` block.

A clean future improvement: add an `--output-dir` equivalent to the Web UI and retire the symlink hack.

## SBOM output layout

```
output/<repo-name>/
├── _manifest/spdx_2.2/manifest.spdx.json   # sbom-tool (set via output_subpath)
├── syft-sbom.json
├── trivy-sbom.json
├── dependency-graph-sbom.json
├── custom-sbom.json                         # optional user upload
├── unified_sbom.json                       # ★ final unified SBOM (merged + enriched)
└── analysis/
    └── <repo-name>_spdx_comparison.csv     # SPDX field coverage
```

Filenames have a single source of truth: `ToolEntry.output_filename` (and `output_subpath`). `pipeline.py` and `analyze/` look them up via `REGISTRY.filename_for(name)`, so changing a filename is a one-line edit on the `ToolEntry`.

## Web UI architecture

`src/sbom_unifier/web/`:

```
app.py              Flask route definitions
  /                  index.html (form)
  /run               start a job (form POST)
  /job/<id>          job detail
  /api/job/<id>      job state + logs as JSON (frontend polling)
  /jobs              job history listing
  /download/<id>     unified_sbom.json
  /download_all/<id> all artifacts as a zip
  /settings/token    save GITHUB_TOKEN to .env (does not survive in Docker)

jobs.py
  PipelineJob        dataclass for a running job
  JOBS               in-memory dict, job_id → PipelineJob
  register_job()     registers in both the in-memory dict and SQLite

db.py
  jobs.db            SQLite. Single table `jobs` (job_id PK, url, status, logs_json, ...)
  insert_job/update_job/get_job_row/list_jobs
```

### Concurrency

Each job runs `pipeline.run_pipeline()` on its own `threading.Thread` (in `web/app.py`'s `/run` handler). Flask's dev server (Werkzeug) handles this fine within the GIL.

Logs are appended to `PipelineJob.logs: list[str]`, with `stdout` captured per job via `contextlib.redirect_stdout` (see `jobs.py`).

### Persistence boundaries

- **Survives a restart**: `jobs.db` history (URL, tool config, status, final logs); SBOM files under `output/<repo>/`
- **Lost on restart**: the `JOBS` in-memory dict (real-time state of running jobs); flash messages; `os.environ["GITHUB_TOKEN"]` (the Web UI's "save" button writes to `.env`, but that file is not on the persisted volume in Docker)

`web/app.py:88` (`index()`) and the `/jobs` route reconstruct missing in-memory jobs from `db.get_job_row()` and return them as a `_JobView` (read-only dataclass). After a restart, completed jobs are still browsable via the detail page, but cannot be re-run.

### SQLite operational notes

- `_init()` does `CREATE TABLE IF NOT EXISTS`, so the DB is created on first job registration (no migration framework)
- Schema changes need updates to `_init()`'s `CREATE TABLE` *and* `insert_job` / `update_job` / `_row_to_view`
- No schema versioning. Adding `PRAGMA user_version` would be a lightweight start when production-grade migrations matter

## CLI architecture

`src/sbom_unifier/cli.py` is a thin argparse wrapper:

- `--list-tools` formats `REGISTRY.all()`
- Otherwise it just calls `pipeline.run_pipeline(url, enabled_tools, base_tool, merge_order, custom_sbom_path, output_root)`

The **only difference** between CLI and Web UI is the `output_root` argument: the CLI accepts `--output`; the Web UI always passes `None` (= `DEFAULT_OUTPUT_DIR`).

## Module dependency graph

```
cli ─┐
     ├─→ pipeline ──→ clone
web ─┘             ├─→ tools/ (REGISTRY) ──→ tools/<name>.py (subprocess)
                   ├─→ merge/
                   ├─→ enrichment/ (file_types, ninka)
                   └─→ analyze/

web/app ──→ web/jobs ──→ web/db (SQLite)
        └─→ pipeline (in a thread)
```

Arrows point in the import direction. There are no reverse dependencies (e.g., `tools/` does not import `pipeline`). This is a convention to keep cycles out.

## Extension points

| Goal | File(s) to touch |
|---|---|
| Add a new SBOM generator | `tools/<new>.py` + `tools/__init__.py` (details: [adding-tools.md](adding-tools.md)) |
| Change merge rules (field priority) | `merge/fields.py`, `merge/merger.py` |
| Add a new enrichment | `enrichment/<new>.py` + invoke from `enrichment/__init__.py:enrich_sbom()` |
| Add SPDX analysis fields | `analyze/spdx_fields.py` (the field list) and `analyze/analyzer.py` |
| Add a new Web UI page | new route in `web/app.py` + `web/templates/<new>.html` |
| Add a job state (e.g. `cancelled`) | `PipelineJob.status` allowed values in `web/jobs.py` + the SQL in `web/db.py` |

## Known debt and improvement candidates

- The Web UI has no `output_dir` override → root cause of the Docker symlink hack. Add an `--output-dir`-equivalent (env var or config) like the CLI has
- `web/app.py` is getting heavy (routes + validation + file upload all in one). Consider splitting routes into separate files or using a Flask blueprint
- `pipeline.py`'s `print()`-based logging assumes Flask captures stdout. Migrating to the standard `logging` module would make tests and debugging easier
- No SQLite schema versioning (manual handling when migrations are needed)
- The 55% coverage floor reflects current reality. Push it up whenever you add new logic
