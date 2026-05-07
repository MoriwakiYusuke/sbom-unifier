# Pin to linux/amd64: sbom-tool ships only an x64 self-contained binary.
# Override with --build-arg IMAGE_PLATFORM=linux/arm64 if you have an arm64
# sbom-tool drop-in (none is currently bundled).
ARG IMAGE_PLATFORM=linux/amd64
FROM --platform=${IMAGE_PLATFORM} python:3.13-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        curl \
        wget \
        ca-certificates \
        perl \
        libdigest-sha-perl \
        libregexp-common-perl \
        libio-captureoutput-perl \
        make \
    && rm -rf /var/lib/apt/lists/*

# Microsoft sbom-tool (self-contained, dotnet runtime not required)
ARG SBOM_TOOL_VERSION=4.1.5
# DOTNET_SYSTEM_GLOBALIZATION_INVARIANT avoids the libicu dependency on slim images
ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
RUN wget -q -O /usr/local/bin/sbom-tool \
        "https://github.com/microsoft/sbom-tool/releases/download/v${SBOM_TOOL_VERSION}/sbom-tool-linux-x64" \
    && chmod +x /usr/local/bin/sbom-tool

# Syft
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
        | sh -s -- -b /usr/local/bin

# Trivy
RUN curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
        | sh -s -- -b /usr/local/bin

# ninka (license/copyright extractor)
RUN git clone --depth 1 https://github.com/dmgerman/ninka /opt/ninka \
    && cd /opt/ninka \
    && perl Makefile.PL \
    && make \
    && make install

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir -e .

# DEFAULT_OUTPUT_DIR is computed as Path(__file__).resolve().parent / "output",
# so it resolves to /app/src/sbom_unifier/output. Symlink that to /app/output
# so users can bind-mount the friendly path: -v $(pwd)/output:/app/output.
RUN mkdir -p /app/output \
    && ln -sfn /app/output /app/src/sbom_unifier/output

# Declare /app/output as a volume so persistence works even without -v.
# Caveat: anonymous volumes + --rm means a fresh volume per run (jobs.db
# resets each time). For cross-run persistence, pass an explicit -v
# (bind mount or named volume).
VOLUME ["/app/output"]

EXPOSE 5000

CMD ["sbom-unifier-web", "--host", "0.0.0.0"]
