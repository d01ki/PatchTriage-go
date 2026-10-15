# PatchTriage (Go) - reproducible container build.
#
#   docker build -t patchtriage .
#   mkdir -p out && docker run --rm -v "$PWD/out:/out" patchtriage   # offline demo
#   docker run --rm -v "$PWD:/work" patchtriage run /work/trivy.json -o /work/report.json

FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /patchtriage ./cmd/patchtriage

# Pin the static repository scanner used by the opt-in local importer and the
# remediation rescan. Source scanning reads manifests/lockfiles; PatchTriage
# never runs the scanner's fix command on untrusted content.
FROM ghcr.io/google/osv-scanner:v2.3.8 AS osv-scanner

FROM debian:trixie-slim
LABEL org.opencontainers.image.title="PatchTriage" \
      org.opencontainers.image.description="Evidence-driven patch triage with deterministic SSVC decisions and audited AI explanations" \
      org.opencontainers.image.source="https://github.com/d01ki/PatchTriage-go"
# git: repository import and remediation; npm: lockfile refresh.
RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates git nodejs npm \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 patchtriage \
    && mkdir -p /out /work \
       /home/patchtriage/.cache/patchtriage-go \
       /home/patchtriage/.config/patchtriage-go \
    && chown -R patchtriage:patchtriage /out /work /home/patchtriage
# Pre-created, user-owned cache/config dirs make Docker initialize the named
# volumes mounted there with uid 1000 ownership.
COPY --from=osv-scanner /osv-scanner /usr/local/bin/osv-scanner
COPY --from=build /patchtriage /usr/local/bin/patchtriage
USER patchtriage
WORKDIR /work
ENTRYPOINT ["patchtriage"]
# `docker run patchtriage` runs the fully offline demo.
CMD ["demo", "--html", "/out/demo_report.html", "--output", "/out/demo_report.json"]
