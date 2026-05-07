# sbom-unifier

A Web UI that takes a GitHub URL and runs a generate → merge → enrich → analyze pipeline to produce an SPDX SBOM.

## Requirements

- Docker

## Quick start

Pick one of the two paths below.

### From Docker Hub

Pull the image and start the Web UI:

```bash
docker pull yusukemoriwaki/sbom-unifier:latest
docker run -p 5000:5000 yusukemoriwaki/sbom-unifier
# → open http://127.0.0.1:5000 in a browser
```

### Building from source

1. Clone the repository:

   ```bash
   git clone https://github.com/MoriwakiYusuke/sbom-unifier.git
   cd sbom-unifier
   ```

2. Build the image and start the Web UI:

   ```bash
   docker build -t sbom-unifier .
   docker run -p 5000:5000 sbom-unifier
   # → open http://127.0.0.1:5000 in a browser
   ```

### Persisting data

Generated SBOMs and the job-history DB (`jobs.db`) live under `/app/output` in the
container. Mount it to keep them on the host across restarts:

```bash
docker run -p 5000:5000 -v "$(pwd)/sbom-output:/app/output" yusukemoriwaki/sbom-unifier
```

## Usage

Watch a short end-to-end demo, or follow the steps below.

[![Watch the SBOM Unifier demo on YouTube](https://img.youtube.com/vi/QgjcEADFB1w/maxresdefault.jpg)](https://youtu.be/QgjcEADFB1w)

1. Open the Web UI at <http://127.0.0.1:5000>.
2. Enter a GitHub repository URL, pick which source tools to run, and (optionally)
   choose the base SBOM and merge order.
3. Press **Run** and watch the live log on the job page.
4. When the job completes, click **Download unified SBOM** to get the composed
   `unified_sbom.json`.

![The run form: GitHub URL, source tools, and merge order](docs/images/web-run-form.png)

See **[docs/usage.md](docs/usage.md)** for the full walkthrough with a screenshot
of each step.

## Replication package

Scripts and data to reproduce the evaluation:
[MoriwakiYusuke/sbom-unifier-replication](https://github.com/MoriwakiYusuke/sbom-unifier-replication).

## Developer documentation

- [docs/development.md](docs/development.md) — local setup, tests, lint, type checking
- [docs/architecture.md](docs/architecture.md) — pipeline structure, module responsibilities, Web UI design
- [docs/adding-tools.md](docs/adding-tools.md) — how to plug in a new SBOM generator

## License

MIT License (see [LICENSE](LICENSE)).

Primary library dependencies:
- Flask: BSD-3-Clause
- python-dotenv: BSD-3-Clause
- requests: Apache-2.0

External tools invoked via subprocess:
- syft / trivy: Apache-2.0
- Microsoft sbom-tool: MIT
- ninka: GPL (invoked via subprocess, so it does not affect this project's license)
