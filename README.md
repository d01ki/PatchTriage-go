# PatchTriage (Go)

PatchTriage turns scanner evidence into patch deployment decisions for a
specific environment. It ingests vulnerability scans or SBOMs, deduplicates
findings, adds exploitation and vendor evidence, and applies the deterministic
[CERT/CC SSVC Deployer model](https://certcc.github.io/SSVC/howto/deployer_tree/)
(`ssvc:DT_DP:1.0.0`).

The output is an action queue in which each item has one of four SSVC outcomes:
**Immediate**, **Out-of-Cycle**, **Scheduled** or **Defer**.

This repository is the Go port of the Python PatchTriage 0.6.0. It builds a
single static binary with the GUI, the offline demo data and the SSVC
validation tables embedded. Decisions match the Python implementation: golden
reports produced by the Python version are part of the test suite.

> AI never chooses the SSVC outcome and never invents a score. Optional AI
> backends only improve explanations. Their outcome, action, deadline and
> numeric claims are checked against the deterministic result, and any
> conflict is flagged.

## Install

```bash
go install github.com/d01ki/PatchTriage-go/cmd/patchtriage@latest
# or, from a checkout
go build -o patchtriage ./cmd/patchtriage
```

Go 1.27 or later. The binary has no runtime dependencies. Repository scanning
and `remediate` additionally use `git`, and `osv-scanner` / `npm` / `pnpm` /
`uv` when they are installed.

## Quick start

```bash
patchtriage demo      # fully offline, bundled evidence -> demo_report.html / .json
patchtriage serve     # GUI console on http://127.0.0.1:8765
patchtriage start     # guided run: answer a few questions, get a patch plan
patchtriage setup     # optional: AI provider, API keys and default backend
```

| Command | Purpose |
|---|---|
| `run FILES...` | Trivy / Grype / osv-scanner JSON or CycloneDX / SPDX SBOM -> decisions, JSON and HTML reports |
| `demo` | Offline demonstration with bundled EPSS / KEV / NVD / Vulnrichment snapshots |
| `verify` | Offline SSVC conformance and reproducibility proof |
| `serve` | Web GUI (anonymous isolated workspaces, targets, uploads, repository import) |
| `start` | Guided run on files or a repository URL, with an optional hand-off to `remediate` |
| `setup` | First-run wizard; keys are validated live and saved privately |
| `fleet URL` | Import a GitHub account's repositories and build one cross-target queue |
| `remediate` | Apply one confirmed upgrade in an isolated Git clone and emit a reviewable patch |

Run `patchtriage <command> -h` to list a command's flags.

## Scriptable usage

```bash
# Scanner output to JSON and self-contained HTML reports
patchtriage run trivy.json grype.json --assets assets.yaml --html report.html -o report.json

# SBOM to assessed findings through OSV.dev (version constraints are resolved
# through the package registries)
patchtriage run sbom.spdx.json --html report.html

# Explicit target context without an inventory
patchtriage run trivy.json --ssvc-exposure open --ssvc-mission-impact mef_failure --ssvc-safety-impact critical

# CISA BOD 26-04 inputs (separate policy; never changes the SSVC result)
patchtriage run trivy.json --bod2604 voluntary --publicly-exposed yes

# Faster runs: skip NVD (EPSS and CISA KEV remain), or vendor advisories
patchtriage run trivy.json --no-nvd
patchtriage run trivy.json --no-vendor-advisories
```

Example `assets.yaml`:

```yaml
assets:
  - match: "web-frontend*"
    system_exposure: open
    mission_impact: mef_failure
    safety_impact: critical
```

Unknown inputs use SSVC's conservative defaults and are flagged for
confirmation. They are never treated as safe.

## Fleet

```bash
patchtriage fleet https://github.com/your-org --limit 10 \
  --ssvc-exposure controlled --html fleet_report.html -o fleet.json
```

Each repository becomes a target in the local store, with its Dependency Graph
SBOM attached. No clone and no execution are involved; the import uses the same
code as a single-repository GUI import. Each target is assessed separately, and
the results are merged into one queue ordered by outcome. Aggregation never
re-decides anything. Forks and archived repositories are skipped unless you opt
in. A rate limit or a quota stops the import with a visible reason. Unassessed
targets are listed but excluded from every total.

## Apply and verify a dependency patch

```bash
patchtriage run osv.json -o report.json
patchtriage remediate report.json --repository ./app --output-dir ./out/app-remediation --check "npm test"
patchtriage remediate            # guided: asks for every missing input
```

`remediate` clones the committed `HEAD` into the output directory and edits
the dependency declaration. Supported files are `package.json`,
`requirements*.txt`, PEP 621 and Poetry `pyproject.toml`. It then refreshes
`package-lock.json`, `pnpm-lock.yaml` or `uv.lock` with lifecycle scripts
disabled, and runs your checks, which are parsed without a shell. Finally it
rescans with OSV-Scanner when that is available. The output directory receives
`workspace/`, `remediation.patch`, `remediation.json` and the post-change scan.
`remediate` never modifies the source checkout, and it never pushes, merges or
deploys.

## Optional AI explanations

```bash
export PATCHTRIAGE_AI_PROVIDER=anthropic ANTHROPIC_API_KEY=...
patchtriage run trivy.json --triage cascade --html report.html

export PATCHTRIAGE_AI_PROVIDER=ollama PATCHTRIAGE_AI_BASE_URL=http://localhost:11434/v1 PATCHTRIAGE_AI_MODEL=<model>
patchtriage run trivy.json --triage ai
```

| Backend | Behavior |
|---|---|
| `rules` | Deterministic SSVC only. This is the default and suits CI. |
| `ai` | Adds a provider-generated explanation to the deterministic result. |
| `cascade` | Screens every finding with a fast model and escalates urgent, uncertain or audit-failing ones to the deep model. |

Supported providers are `anthropic` (Messages and Message Batches with
`--batch`), `openai` and any OpenAI-compatible endpoint (`openai-compatible`,
`ollama`). PatchTriage never switches provider implicitly. If an API call
fails, that finding falls back to the rules result and is tagged
`rules_fallback`.

## Configuration

Environment variables always win over the file written by `patchtriage setup`
(`~/.config/patchtriage-go/config.json`, mode 0600).

| Variable | Purpose |
|---|---|
| `PATCHTRIAGE_AI_PROVIDER`, `PATCHTRIAGE_AI_MODEL`, `PATCHTRIAGE_AI_SCREEN_MODEL`, `PATCHTRIAGE_AI_DEEP_MODEL`, `PATCHTRIAGE_AI_BASE_URL`, `PATCHTRIAGE_AI_API_KEY` | AI provider selection |
| `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` | Provider credentials (kept separate per provider) |
| `NVD_API_KEY` | Raises the NVD rate limit |
| `GITHUB_TOKEN` / `GH_TOKEN` | Raises GitHub API limits; private repositories in local mode |
| `PATCHTRIAGE_CONFIG_DIR`, `PATCHTRIAGE_CACHE_DIR` | Override `~/.config/patchtriage-go` and `~/.cache/patchtriage-go` |
| `PATCHTRIAGE_DEPLOYMENT_MODE` | `local` (default) or `public`; public mode never uses server tokens for imports |
| `PATCHTRIAGE_ALLOW_GENERIC_REPOSITORIES` | Opt-in local OSV-Scanner import for non-GitHub HTTPS Git hosts |
| `PATCHTRIAGE_COOKIE_SECURE` | `auto` (from `X-Forwarded-Proto`), `true` or `false` |
| `PATCHTRIAGE_MAX_*` | GUI limits (request/source bytes, targets, jobs, fleet import size) |

## Docker

```bash
docker compose up gui                       # GUI on http://localhost:8765
docker compose run --rm demo                # offline demo -> ./out/demo_report.html
docker compose run --rm start               # guided run; this directory is /work
docker compose run --rm triage run /work/sbom.json -o /out/report.json --html /out/report.html
```

The image bundles `git`, `npm` and a pinned `osv-scanner`, and runs as an
unprivileged user. Targets, evidence and caches persist in named volumes. For
a hosted deployment behind TLS, set `PATCHTRIAGE_DEPLOYMENT_MODE=public`,
`PATCHTRIAGE_ALLOW_GENERIC_REPOSITORIES=false` and
`PATCHTRIAGE_COOKIE_SECURE=true`.

## Reproducibility

```bash
patchtriage verify --repeats 100 --output verification_report.json
```

`verify` runs offline and checks the following:

- all 72 SSVC Deployer paths;
- all 16 Human Impact combinations;
- that target context reaches the engine unchanged;
- that unknown context is handled conservatively;
- that repeated decisions produce identical hashes;
- that the frozen end-to-end pipeline still produces the same result;
- that altered outcomes, actions or deadlines are detected.

Compare `input_fingerprint` and `decision_fingerprint` across runs.

## Limits

- PatchTriage is not a replacement for a vulnerability scanner. An empty
  result is not proof that a target is secure. Inputs that are unsupported or
  inaccessible are reported as `coverage_incomplete`, never as a clean result.
- SSVC depends on accurate organizational context and current threat evidence.
  Human review remains required for inferred inputs.
- Automatic patching covers direct npm and Python dependency declarations only.

## Development

```bash
go vet ./...
go test ./...
```

Tests never reach the network. The files under `testdata/golden/` and
`testdata/*_python.json` were produced by the Python implementation (see
`testdata/golden/gen_golden.py`). They are the reference for decision parity:
regenerate them from Python and never from this engine.
