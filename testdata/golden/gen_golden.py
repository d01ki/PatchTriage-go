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


if __name__ == "__main__":
    main()
