# Development Guide

Setup and day-to-day commands for anyone taking over this project. For the codebase architecture itself, see [architecture.md](architecture.md).

## Choosing a development environment

Day-to-day work is usually fastest on the **host directly (venv)**. Docker is for the final smoke check and CI.

| Use case | Recommended |
|---|---|
| Unit tests, lint, type-check | Host venv |
| Real SBOM generation (needs external tools) | Host venv (also needs the tools) or Docker |
| Pre-release end-to-end check | Docker (`docker build && docker run`) |

## Host venv setup

### Prerequisites

- Python 3.13+ (`pyproject.toml` declares `requires-python = ">=3.13"`)
- git
- External SBOM tools (only if you want to run the real pipeline):
  - [Microsoft sbom-tool v4.1.5+](https://github.com/microsoft/sbom-tool/releases) — drop the single binary at e.g. `/usr/local/bin/sbom-tool`
  - [Syft](https://github.com/anchore/syft) — `curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin`
  - [Trivy](https://github.com/aquasecurity/trivy) — `curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin`
  - [ninka](https://github.com/dmgerman/ninka) — `git clone && cd ninka && perl Makefile.PL && make && sudo make install` (requires Perl and `IO::CaptureOutput`)

Use the same versions and install methods as the [Dockerfile](../Dockerfile) to minimize behavioral drift between host and container runs.

### Install

```bash
git clone <repo-url>
cd sbom-unifier
python3.13 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Environment variables

Only needed if you exercise tests or runs that hit the GitHub Dependency Graph:

```bash
export GITHUB_TOKEN="ghp_xxxxxxxxxxxxxxxx"
```

Tests pass without it (public repos work unauthenticated; rate-limited).

## Day-to-day commands

### Lint, format, type-check

```bash
ruff check .                # static analysis
ruff format --check .       # format check (fails on diff)
ruff format .               # auto-format (run before commit)
mypy sbom_unifier        # type check (not strict, but warn_unused_ignores etc. are on)
```

### Tests

```bash
pytest                                          # full run (enforces 55% coverage threshold)
pytest tests/test_pipeline.py -v                # one file
pytest -k "snapshot" -v                         # filter by name
pytest --cov-report=html                        # HTML coverage report → htmlcov/
```

### Self-containment check

The `sbom-unifier` package was historically merged from separate `sbom_generator` / `sbom_merge` / `sbom_analyzer` packages. A grep guards against leftover imports:

```bash
grep -rE 'from sbom_(generator|merge|analyzer)' src/sbom_unifier
# empty output = OK
```

Pre-PR checklist: `ruff check` → `ruff format --check` → `mypy` → `pytest` → the grep above.

## Running the pipeline from the CLI

The `sbom-unifier` console script runs the same pipeline as the Web UI and is
handy for debugging a single repo without the browser. It is a developer tool —
the Web UI is the supported entry point for end users, so the CLI is
intentionally left out of the top-level README.

```bash
# List the registered source tools and their default merge order
sbom-unifier --list-tools

# Run the full pipeline on a repo (all generators, default base/merge order)
sbom-unifier https://github.com/pallets/flask

# Pick specific tools, base, and output directory
sbom-unifier https://github.com/pallets/flask \
    --tools syft trivy \
    --base-tool syft \
    --output ./out
```

| Flag | Meaning |
|---|---|
| `--tools`, `-t` | Subset of generators to run (default: all) |
| `--base-tool` | Base SBOM the others merge into (default: first base candidate) |
| `--custom-sbom` | Path to a user-supplied SBOM merged at the end |
| `--output`, `-o` | Output root directory (default: `<package>/output`) |
| `--list-tools` | Print the registered tools and exit |

The only behavioral difference from the Web UI is `--output`: the CLI can set the
output root, while the Web UI always uses `DEFAULT_OUTPUT_DIR`. See
[architecture.md](architecture.md#cli-architecture).

## Sanity check via Docker

```bash
docker build -t sbom-unifier .
docker run --rm -v $(pwd)/output:/app/output -e GITHUB_TOKEN=$GITHUB_TOKEN \
    sbom-unifier sbom-unifier https://github.com/pallets/flask --tools syft
ls output/flask/unified_sbom.json   # generated artifact lands on the host
```

The container runs as root, so files under host `output/` end up owned by root. Reset ownership when you need to edit them on the host: `sudo chown -R $(id -u):$(id -g) output`.

## Adding a new SBOM tool

See [adding-tools.md](adding-tools.md) for the procedure. Drop one file at `src/sbom_unifier/tools/<name>.py` and add one line to `tools/__init__.py` — the new tool surfaces automatically across CLI, Web UI, and the merge order.

## Test strategy

- Snapshot tests under `tests/fixtures/tiny-project/` (hand-written sbom-tool / syft / trivy / dependency-graph SBOMs) form the core
- Regenerating expected outputs: `rm tests/fixtures/tiny-project/expected/unified_sbom.json && pytest tests/test_snapshot.py` → eyeball the diff, then commit
- Don't aggressively mock subprocess calls to external tools (syft etc.) with `responses` or `pytest-mock`; prefer testing the pure merge / enrichment / analyze logic
- Coverage threshold is 55% (`pyproject.toml`), set low because the generator wrappers (subprocess) and Flask routes are thin. Push it up whenever you touch logic.

## Directory layout

```
src/sbom_unifier/
├── cli.py              # `sbom-unifier` entry point (argparse)
├── pipeline.py         # full pipeline orchestration
├── clone.py            # GitHub URL parsing and git clone
├── config.py           # constants like DEFAULT_OUTPUT_DIR
├── tools/              # self-registering modules per SBOM generator
│   ├── registry.py     # ToolEntry / ToolRegistry
│   ├── sbom_tool.py    # Microsoft sbom-tool wrapper
│   ├── syft.py         # Syft wrapper
│   ├── trivy.py        # Trivy wrapper
│   ├── github.py       # GitHub Dependency Graph API
│   └── manual.py       # slot for user-uploaded SBOMs
├── merge/              # take the base SBOM and merge other tools' outputs into it
├── enrichment/         # file_types and ninka backfills
├── analyze/            # SPDX field-coverage CSV
└── web/
    ├── app.py          # Flask routes
    ├── jobs.py         # in-memory job state (PipelineJob, JOBS dict)
    └── db.py           # SQLite (jobs.db) job-history persistence

tests/                  # snapshot + semantic + unit
docs/                   # developer documentation
docs/superpowers/       # brainstorming / spec / plan records (reference material)
```

For detailed module responsibilities and dependencies, see [architecture.md](architecture.md).
