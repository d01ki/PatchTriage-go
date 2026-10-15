"""Regenerate the golden reports from the Python PatchTriage implementation.

Usage (from the repository root, with Python PatchTriage 0.6.0 installed in a
virtual environment; never run against the source checkout in place):

    <venv>/python -I testdata/golden/gen_golden.py

Every case runs offline: enrichment comes from the bundled demo snapshot and
OSV.dev is replaced by testdata/osv_responses.json. Timestamps are replaced
with "<time>" so the files are stable.
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "testdata" / "golden"
DATA = ROOT / "data"
TIME_KEYS = {"enriched_at", "detected_at", "first_seen"}

# Isolate every cache and configuration write from the user's real directories.
_scratch = tempfile.mkdtemp(prefix="patchtriage-golden-")
os.environ["PATCHTRIAGE_CACHE_DIR"] = str(Path(_scratch) / "cache")
os.environ["PATCHTRIAGE_CONFIG_DIR"] = str(Path(_scratch) / "config")

import httpx  # noqa: E402

from patchtriage.assess import assess  # noqa: E402
from patchtriage.bod2604 import summarize as summarize_response_policy  # noqa: E402
from patchtriage.models import Asset  # noqa: E402


def _osv_transport() -> httpx.MockTransport:
    responses = json.loads((ROOT / "testdata" / "osv_responses.json").read_text("utf-8"))

    def key(query: dict) -> str:
        package = query.get("package") or {}
        if package.get("purl"):
            return package["purl"]
        return f"{package.get('ecosystem')}:{package.get('name')}@{query.get('version', '')}"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/querybatch":
            queries = json.loads(request.content)["queries"]
            return httpx.Response(200, json={"results": [
                {"vulns": [{"id": vid} for vid in responses["queries"].get(key(q), [])]}
                for q in queries]})
        vid = request.url.path.rsplit("/", 1)[-1]
        if vid in responses["vulns"]:
            return httpx.Response(200, json=responses["vulns"][vid])
        return httpx.Response(404, json={"code": 5, "message": "Bug not found"})

    return httpx.MockTransport(handler)


_RealClient = httpx.Client
httpx.Client = lambda **kwargs: _RealClient(transport=_osv_transport(), **kwargs)


def _normalize(value):
    if isinstance(value, dict):
        return {k: ("<time>" if k in TIME_KEYS and v is not None else _normalize(v))
                for k, v in value.items()}
    if isinstance(value, list):
        return [_normalize(v) for v in value]
    return value


def _write(name: str, report: dict) -> None:
    text = json.dumps(_normalize(report), indent=2, sort_keys=True, default=str)
    (GOLDEN / f"{name}.json").write_text(text + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {name}.json")


def _snapshot() -> dict:
    return {name: json.loads((DATA / f"demo_{name}.json").read_text("utf-8"))
            for name in ("epss", "kev", "nvd", "vulnrichment")}


def _report(result) -> dict:
    # Same shape as patchtriage.cli._emit.
    return {
        "findings": [f.model_dump(mode="json") for f in result.findings],
        "actions": [a.model_dump(mode="json") for a in result.actions],
        "evaluation": [r.model_dump(mode="json") for r in result.eval_rows],
        "response_policy": summarize_response_policy(result.findings),
        "coverage": result.coverage,
    }


CONTEXT = Asset(identifier="", kind="host", system_exposure="open",
                mission_impact="mission_failure", safety_impact="catastrophic",
                publicly_exposed="yes", bod2604_applicability="voluntary")

CASES = {
    "trivy": dict(files=[DATA / "fixtures" / "trivy_sample.json"]),
    "grype": dict(files=[DATA / "fixtures" / "grype_sample.json"]),
    "trivy_grype_inventory": dict(
        files=[DATA / "fixtures" / "trivy_sample.json", DATA / "fixtures" / "grype_sample.json"],
        inventory=DATA / "demo_assets.yaml"),
    "trivy_context": dict(files=[DATA / "fixtures" / "trivy_sample.json"], asset=CONTEXT),
    "osv_scanner": dict(files=[ROOT / "testdata" / "osv_scanner_sample.json"]),
    "sbom_cyclonedx": dict(files=[ROOT / "testdata" / "sbom_cyclonedx.json"]),
    "sbom_spdx": dict(files=[ROOT / "testdata" / "sbom_spdx.json"]),
}


def main() -> None:
    for name, case in CASES.items():
        result = assess(case["files"], asset=case.get("asset"),
                        inventory=case.get("inventory"),
                        provider_status="provider_reported",
                        snapshot=_snapshot(), vendor_sources=None)
        _write(name, _report(result))

    # The GUI demo target, created exactly like POST /api/demo, then run.
    from patchtriage import targets as tstore
    from patchtriage.webapp.runner import run_target
    target = tstore.add_target(
        name="Demo", criticality="critical", internet_exposed=True,
        reachable=True, runtime_observed=True, system_exposure="open",
        mission_impact="mef_failure", safety_impact="critical",
        context_sources=["OpenTelemetry", "Falco"], demo=True)
    tstore.save_source(
        target["id"], (DATA / "fixtures" / "trivy_sample.json").read_text("utf-8"),
        "trivy", filename="trivy_sample.json", source_kind="demo",
        provenance={"provider": "bundled-demo", "offline": True,
                    "coverage": {"status": "complete",
                                 "reason": "Bundled scanner fixture"}})
    summary = run_target(tstore.get_target(target["id"]), backend="rules")
    for volatile in ("target_id", "report_url", "duration_ms"):
        summary.pop(volatile, None)
    _write("web_demo_summary", summary)

    # The CLI demo seeds an isolated cache and runs the regular enrichment.
    with tempfile.TemporaryDirectory() as work:
        out = Path(work) / "demo.json"
        subprocess.run([sys.executable, "-I", "-m", "patchtriage.cli", "demo",
                        "--html", str(Path(work) / "demo.html"), "--output", str(out)],
                       cwd=work, check=True, stdout=subprocess.DEVNULL)
        _write("demo", json.loads(out.read_text("utf-8")))
        html = (Path(work) / "demo.html").read_text("utf-8")
        (GOLDEN / "demo.html").write_text(html, encoding="utf-8", newline="\n")
        print("wrote demo.html")


# Constraint-to-release choices (patchtriage.ingest.versions.choose) over
# release lists shaped like real registry answers.
CHOOSE_RELEASES = {
    "semver": ["0.0.3", "0.0.4", "0.2.3", "0.2.9", "0.3.0", "1.2.3", "1.2.9", "1.3.0",
               "1.9.0", "2.0.0", "2.1.0rc1", "2.0.1"],
    "pep440": ["1.0", "1.0.0", "1.0.post1", "1.0.1", "1.1.dev0", "1.1", "1.4.5", "1.4.10",
               "1!0.5", "2.0a1", "2.0", "2.0.0.1", "01.5", "3.0+local", "10.0"],
    "tags": ["v5.0.0", "v6", "v6.0.0", "v6.0.1", "v6.1", "v7.0.0-beta", "6", "v6.0"],
    "none": ["1.0a1", "2.0rc1"],
}
CHOOSE_CONSTRAINTS = [
    "", "*", "x", "1", "1.*", "1.*.*", "1.x", "1.x.x", "v1.*", "6.*.*", "6.0.*", "1.*.3",
    "==1.2.*", "==1.*", "!=1.0.*", "== 1.0", "==1.0", "==1.0.0", "= 1.3.0", "=1.0",
    "^1.2.3", "^0.2.3", "^0.0.3", "^0", "^0.0", "^1", "~1.2.3", "~1.2", "~1", "^ v1.2",
    "~=1.0", "~=1.4.5", "~=1", "~= 2.0", ">=1.2, <1.3", ">= 1.2.3 < 2", ">=1.2.4", ">1.0",
    ">1.0.0", ">=v1.0", "<1.3", "<=1.4.5", "<2", "<2.0", ">=1.0,<2.0,!=1.4.5", "> 1.0 < 2",
    ">=1.0 <2 !=1.0.1", "===1.0", "===1.0.post1", "1.2.3", "latest", "main", "release/v1",
    "1.2.3 || 2.0.0", ">=9", "^9.0.0", ">=1.0,,<1.1", ">=1!0", "!=2.0", "<1.0.post1",
    ">=1.0.post1", ">0.9", ">=0.0.0", "v6", "6", ">=1.0a1",
]


def choose_cases() -> None:
    from patchtriage.ingest import versions
    cases = []
    for set_name, values in CHOOSE_RELEASES.items():
        releases = versions._releases(values, strip_v=set_name == "tags")
        for preferred in ("", "1.3.0", "6.0.0"):
            for constraint in CHOOSE_CONSTRAINTS:
                if preferred and constraint:
                    continue
                case = {"releases": set_name, "constraint": constraint, "preferred": preferred}
                try:
                    chosen, basis = versions.choose(releases, constraint, preferred)
                    case.update(version=chosen.version, basis=basis)
                except versions.ResolutionError as exc:
                    case["error"] = str(exc)
                cases.append(case)
    out = ROOT / "testdata" / "choose_python.json"
    out.write_text(json.dumps({"releases": CHOOSE_RELEASES, "cases": cases}, indent=1) + "\n",
                   encoding="utf-8", newline="\n")
    print("wrote choose_python.json")


# Manifest ranges (patchtriage.ingest.versions.declared_constraints).
MANIFESTS = {
    "requirements.txt": (
        "# core\nfastapi>=0.104.0\nuvicorn[standard]>=0.24.0  # server\n"
        "-r dev.txt\ngit+https://example.com/x.git\nflask \\\n  >=2.0\n"
        "Pillow>=10.1.0\nDjango (>=3.2, <4)\nrequests>=2.0 ; python_version > '3.8'\n"
        "attrs==23.*\nbad name>=1\nnumpy>=1.0,\nzope.interface~=5.4\nmy_pkg @ file.whl\n"
        "six\r\nclick!=8.0.0,>=7\n"),
    "pyproject.toml": (
        '[project]\ndependencies = ["pillow<12", "httpx", "Django>=4.0"]\n'
        '[project.optional-dependencies]\ndev = ["pytest>=7", "fastapi<1"]\ndocs = ["sphinx"]\n'
        '[build-system]\nrequires = ["setuptools>=68"]\n'
        '[dependency-groups]\ntest = ["coverage>=7", {include-group = "dev"}]\n'
        '[tool.poetry.dependencies]\npython = "^3.10"\n'
        'requests = {version = "^2.31", extras = ["socks"]}\nrich = "*"\n'
        '[tool.poetry.group.lint.dependencies]\nruff = "^0.4"\n'),
    "app/package.json": json.dumps({
        "dependencies": {"react": "^18.2.0", "local": "file:../x", "num": 5},
        "devDependencies": {"lodash": "*", "react": "^17"},
        "optionalDependencies": {"fsevents": "latest"}}),
    "app/web/package.json": json.dumps({"dependencies": {"react": "^16", "vue": "3.x"}}),
    "svc/requirements/prod.txt": "fastapi<0.200\nPILLOW>=9\n",
    "broken/package.json": "{not json",
    "broken/pyproject.toml": "[project\n",
    "odd/pyproject.toml": 'project = "x"\n',
}
MANIFEST_PATHS = [
    "requirements.txt", "requirements-dev.in", "dev-requirements.txt", "requirements/prod.txt",
    "svc/pyproject.toml", "web/package.json", "web/node_modules/x/package.json", "setup.py",
    "notes.txt", "package-lock.json", "vendor/requirements.txt", "REQUIREMENTS.TXT", "a/b/Requirements-x.in",
]


def manifest_cases() -> None:
    from patchtriage.ingest import versions
    constraints, warnings = versions.declared_constraints(MANIFESTS)
    out = ROOT / "testdata" / "manifests_python.json"
    out.write_text(json.dumps({
        "manifests": MANIFESTS,
        "constraints": sorted([eco, name, spec, paths] for (eco, name), (spec, paths) in constraints.items()),
        "warning_paths": [w.split(" could not be parsed")[0] for w in warnings],
        "is_manifest": {p: versions.is_manifest(p) for p in MANIFEST_PATHS},
    }, indent=1) + "\n", encoding="utf-8", newline="\n")
    print("wrote manifests_python.json")


# AI recommendation merge + audit (patchtriage.triage.engine / audit) over
# the findings of existing golden reports. "<baseline>" is replaced by the
# finding's deterministic action.
AI_RECOMMENDATIONS = [
    {"action": "<baseline>", "rationale": "Explain the supplied SSVC path.",
     "remediation_steps": ["Review the vendor advisory."], "uncertainties": []},
    {"action": "<baseline>", "rationale": "EPSS of 0.99 suggests high risk.",
     "remediation_steps": ["Upgrade within 3 days"], "uncertainties": []},
    {"action": "monitor", "rationale": "  Low urgency.  ", "remediation_steps": [], "uncertainties": ["  "]},
    {"action": "patch_immediately", "rationale": "Escalate.", "remediation_steps": [], "uncertainties": []},
    {"action": "<baseline>", "rationale": "There is no known exploitation of this flaw.",
     "remediation_steps": [], "uncertainties": ["exploitation unlikely within 30 days"]},
    {"action": "<baseline>", "rationale": "Apply vendor guidance.",
     "remediation_steps": ["Upgrade the package to the latest version", "Install the patch"],
     "uncertainties": ["EPSS percentile 97% may be stale", "CVSS score 9.8 is from NVD"]},
]


def ai_audit_cases() -> None:
    from patchtriage.models import Finding
    from patchtriage.triage.audit import audit_finding
    from patchtriage.triage.engine import (RulesBackend, _merge_ai_recommendation,
                                           _validate_recommendation)
    rules = RulesBackend()
    cases = []
    for golden in ("trivy_context", "grype", "demo"):
        report = json.loads((GOLDEN / f"{golden}.json").read_text("utf-8"))
        for index, raw in enumerate(report["findings"]):
            raw = {k: v for k, v in raw.items() if k != "triage"}
            for key in ("enriched_at",):
                raw["enrichment"][key] = None
            raw.pop("detected_at", None)
            raw.pop("first_seen", None)
            finding = Finding.model_validate(raw)
            baseline = rules.triage(finding)["action"]
            for rec in AI_RECOMMENDATIONS:
                rec = {k: (baseline if v == "<baseline>" else v) for k, v in rec.items()}
                finding.triage = _merge_ai_recommendation(
                    finding, _validate_recommendation(rec), "test:model")
                audit = audit_finding(finding, rules)
                cases.append({"golden": golden, "index": index, "recommendation": rec,
                              "rationale": finding.triage["rationale"],
                              "ai_recommendation": finding.triage["ai_recommendation"],
                              "flags": audit["flags"]})
    out = ROOT / "testdata" / "ai_audit_python.json"
    out.write_text(json.dumps(cases, indent=1) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote ai_audit_python.json ({len(cases)} cases)")


# Manifest edits (patchtriage.remediation.update_dependency_manifests).
REMEDIATION_WORKSPACES = {
    "npm": {
        "package.json": json.dumps({"name": "fixture", "version": "1.0.0", "private": True,
                                    "dependencies": {"zeta": "1.0.0", "lodash": "^4.17.20", "é-pkg": "1"},
                                    "devDependencies": {"Lodash": "4.17.0"}, "scripts": {"t": "a<b&c"},
                                    "nested": {"list": [1, 2.5, None, {"k": []}], "empty": {}}},
                                   indent=2, ensure_ascii=False) + "\n",
        "app/package.json": '{\n    "peerDependencies": {\n        "lodash": "4.x"\n    }\n}',
        "app/node_modules/lodash/package.json": '{"dependencies": {"lodash": "1"}}\n',
        "other/package.json": '{"dependencies": {"left-pad": "1.0.0"}}\n',
    },
    "npm_git": {"package.json": '{"dependencies": {"lodash": "git+https://example.com/lodash.git"}}\n'},
    "npm_missing": {"package.json": '{"dependencies": {"left-pad": "1.0.0"}}\n'},
    "pypi": {
        "requirements.txt": (
            "# core\nrequests[security]>=2.28; python_version >= \"3.10\"  # runtime\n"
            "Requests==2.0\nrequests_toolbelt>=1\n  requests ~= 2.1\nflask\nrequests\n"),
        "requirements-dev.txt": "requests>=2.0,<3\n",
        "requirements.in": "requests\n",
        "docs/requirements.txt": "sphinx\n",
        "pyproject.toml": (
            '[project]\nname = "requests"\nversion = "1"\ndependencies = [\n  "requests>=2.28",\n'
            '  "httpx", "requests[socks]>=2 ; python_version>\'3\'",\n]\nkeywords = ["requests"]\n\n'
            '[project.optional-dependencies]\ntest = ["pytest>=8", \'requests\']\n\n'
            '[dependency-groups]\ndev = ["requests<3"]\n\n'
            '[tool.poetry.dependencies]\npython = "^3.10"\n'
            'requests = { version = "^2.28", extras = ["socks"] }  # http\n'
            '[tool.poetry.group.dev.dependencies]\nrequests = "^2.0"\n'
            '[tool.other]\nrequests = "x"\n'),
    },
    "poetry_bad": {"pyproject.toml": '[tool.poetry.dependencies]\nrequests = { git = "https://x" }\n'},
    "poetry_table": {"pyproject.toml": '[tool.poetry.dependencies]\nrequests = 2\n'},
    "unsupported": {"go.mod": "module x\n"},
}
REMEDIATION_ACTIONS = {
    "npm": ("lodash", "npm"), "npm_git": ("lodash", "npm"), "npm_missing": ("lodash", "npm"),
    "pypi": ("requests", "pypi"), "poetry_bad": ("requests", "pypi"), "poetry_table": ("requests", "pypi"),
    "unsupported": ("x", "golang"),
}


def remediation_cases() -> None:
    from patchtriage.plan import Action
    from patchtriage.remediation import RemediationError, update_dependency_manifests
    cases = {}
    for name, files in REMEDIATION_WORKSPACES.items():
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            for rel, content in files.items():
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).write_bytes(content.encode("utf-8"))
            package, ecosystem = REMEDIATION_ACTIONS[name]
            action = Action(action_id="a", kind="upgrade", summary="s", asset="repo", package=package,
                            ecosystem=ecosystem, installed_version="1", target_version="9.9.9")
            case = {"package": package, "ecosystem": ecosystem}
            try:
                changed = update_dependency_manifests(root, action)
                case["changed"] = sorted(p.relative_to(root).as_posix() for p in changed)
            except RemediationError as exc:
                case["error"] = str(exc)
            case["files"] = {rel: (root / rel).read_bytes().decode("utf-8").replace("\r\n", "\n")
                             for rel in files}
            cases[name] = case
    out = ROOT / "testdata" / "remediation_python.json"
    out.write_text(json.dumps({"workspaces": REMEDIATION_WORKSPACES, "cases": cases}, indent=1,
                              ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    print("wrote remediation_python.json")


# Fleet HTML (patchtriage.report.fleet.render_fleet_html); escaping-sensitive
# values cover every cell the template interpolates.
FLEET_ROLLUP = {'generated_at': '2026-10-15T00:00:00Z',
     'targets_total': 3,
     'targets_assessed': 2,
     'targets_unassessed': 1,
     'findings_total': 7,
     'kev_total': 2,
     'outcomes': {'immediate': 1, 'out_of_cycle': 2, 'scheduled': 3, 'defer': 1},
     'queue': [{'top_priority': 'P1',
                'outcome_label': 'Immediate',
                'deadline_days': 3,
                'target_name': 'acme/<web>',
                'package': 'lodash',
                'installed_version': '4.17.20',
                'target_version': '4.17.21',
                'summary': 'Upgrade lodash & "friends" \'now\'',
                'kev_count': 2,
                'finding_count': 3},
               {'top_priority': 'P3',
                'deadline_days': 30,
                'target_name': 'acme/api',
                'package': 'xz',
                'summary': 'Upgrade xz',
                'kev_count': 0,
                'finding_count': 1},
               {'top_priority': 'PX',
                'outcome_label': '',
                'deadline_days': 90,
                'target_name': 'acme/api',
                'package': 'zlib',
                'target_version': '1.3',
                'summary': 's',
                'finding_count': 1}],
     'queue_truncated': True,
     'coverage_incomplete_targets': 1,
     'targets': [{'name': 'acme/<web>',
                  'assessed': True,
                  'result_state': 'findings_present',
                  'coverage_status': 'provider_reported',
                  'total': 4,
                  'outcomes': {'immediate': 1, 'out_of_cycle': 1, 'scheduled': 2, 'defer': 0},
                  'kev': 2,
                  'report_url': '/report/abc'},
                 {'name': 'acme/api',
                  'assessed': True,
                  'result_state': '',
                  'coverage_status': 'complete',
                  'total': 3,
                  'outcomes': {'immediate': 0, 'out_of_cycle': 1, 'scheduled': 1, 'defer': 1},
                  'kev': 0,
                  'report_url': ''},
                 {'name': 'acme/new', 'assessed': False, 'result_state': 'not_assessed'}]}


def fleet_case() -> None:
    from patchtriage.report.fleet import render_fleet_html
    out = ROOT / "testdata" / "fleet_python.json"
    html = render_fleet_html(FLEET_ROLLUP, title="PatchTriage - Fleet Report - acme")
    out.write_text(json.dumps({"rollup": FLEET_ROLLUP, "html": html}, indent=1, ensure_ascii=False) + "\n",
                   encoding="utf-8", newline="\n")
    print("wrote fleet_python.json")


if __name__ == "__main__":
    main()
    choose_cases()
    manifest_cases()
    ai_audit_cases()
    remediation_cases()
    fleet_case()
