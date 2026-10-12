package ingest

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/d01ki/PatchTriage-go/data"
	"github.com/d01ki/PatchTriage-go/internal/model"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := data.ReadFile("fixtures/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSniffFormat(t *testing.T) {
	cases := map[string]string{
		string(fixture(t, "trivy_sample.json")): "trivy",
		string(fixture(t, "grype_sample.json")): "grype",
		`{"results": []}`:                       "osv",
		`{"results": [{"packages": []}]}`:       "osv",
		`{"results": [{"other": 1}]}`:           "",
		`{}`:                                    "",
		`[1, 2]`:                                "",
	}
	for in, want := range cases {
		if got := SniffFormat([]byte(in)); got != want {
			t.Errorf("SniffFormat(%.40q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseTrivySample(t *testing.T) {
	findings, err := ParseScanner(fixture(t, "trivy_sample.json"), "trivy", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 4 {
		t.Fatalf("got %d findings, want 4", len(findings))
	}
	var xz *model.RawFinding
	for i := range findings {
		if findings[i].VulnID == "CVE-2024-3094" {
			xz = &findings[i]
		}
	}
	if xz == nil {
		t.Fatal("CVE-2024-3094 missing")
	}
	if xz.Severity != model.SeverityCritical || xz.CVSSScore == nil || *xz.CVSSScore != 10.0 ||
		!strings.HasPrefix(xz.Package.FixedVersion, "5.6.1") || xz.SourceScanner != "trivy" {
		t.Errorf("unexpected xz finding: %+v", xz)
	}
	if xz.Asset.Identifier == "" || xz.Asset.SystemExposure != "unknown" {
		t.Errorf("unexpected scanner asset: %+v", xz.Asset)
	}
}

func TestParseGrypeRelatedCVEPreferred(t *testing.T) {
	findings, err := ParseScanner(fixture(t, "grype_sample.json"), "grype", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Package.Name == "lodash" {
			if f.VulnID != "CVE-2021-23337" || !contains(f.Aliases, "GHSA-35jh-r3h4-6jhm") {
				t.Errorf("lodash: vuln_id=%s aliases=%v", f.VulnID, f.Aliases)
			}
			return
		}
	}
	t.Fatal("lodash finding missing")
}

func TestParseGrypeTargetStringAndObject(t *testing.T) {
	for _, target := range []string{`"img:1"`, `{"userInput": "img:1", "imageID": "sha"}`, `{"imageID": "img:1"}`} {
		doc := `{"descriptor": {}, "source": {"type": "image", "target": ` + target + `},
			"matches": [{"vulnerability": {"id": "CVE-2023-1"}, "artifact": {"name": "x", "version": "1"}}]}`
		findings, err := ParseScanner([]byte(doc), "grype", nil)
		if err != nil {
			t.Fatal(err)
		}
		if findings[0].Asset.Identifier != "img:1" || findings[0].Asset.Kind != "image" {
			t.Errorf("target %s -> asset %+v", target, findings[0].Asset)
		}
	}
}

func TestParseOSVScannerUsesPackageSpecificFix(t *testing.T) {
	doc := `{"results": [{"source": {"path": "repo"}, "packages": [{
		"package": {"name": "widget", "ecosystem": "npm", "version": "10.1.0"},
		"vulnerabilities": [{"id": "OSV-TEST-1", "affected": [
			{"package": {"name": "widget", "ecosystem": "PyPI"},
			 "ranges": [{"events": [{"introduced": "0"}, {"fixed": "999.0"}]}]},
			{"package": {"name": "widget", "ecosystem": "npm"},
			 "ranges": [{"type": "SEMVER", "events": [{"introduced": "10.0.0"}, {"fixed": "10.2.0"}]}]}
		]}]}]}]}`
	findings, err := ParseScanner([]byte(doc), "osv", nil)
	if err != nil {
		t.Fatal(err)
	}
	f := findings[0]
	if f.Package.FixedVersion != "10.2.0" || f.Asset.Identifier != "repo" || f.Asset.Kind != "repository" ||
		f.SourceScanner != "osv" || f.Severity != model.SeverityUnknown {
		t.Errorf("unexpected OSV finding: %+v", f)
	}
}

func TestParseScannerKeepsDefaultAsset(t *testing.T) {
	asset := model.NewAsset("web-frontend")
	asset.SystemExposure = "open"
	findings, err := ParseScanner(fixture(t, "trivy_sample.json"), "trivy", &asset)
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Asset.Identifier != "web-frontend" || findings[0].Asset.SystemExposure != "open" {
		t.Errorf("default asset not applied: %+v", findings[0].Asset)
	}
}

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadRejectsMalformedAndUnknown(t *testing.T) {
	for name, content := range map[string]string{
		"truncated.json": `{"Results": [`,
		"unknown.json":   `{"foo": 1}`,
		"array.json":     `[1, 2, 3]`,
	} {
		_, err := LoadFile(context.Background(), writeTemp(t, name, content), "", nil, nil)
		if err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	_, err := LoadFile(context.Background(), writeTemp(t, "unknown.json", `{"foo": 1}`), "", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "Unrecognized format") {
		t.Errorf("unknown format error = %v", err)
	}
}

func TestLoadCRLFAndBOM(t *testing.T) {
	const bom = "\xef\xbb\xbf"
	content := bom + strings.ReplaceAll(string(fixture(t, "trivy_sample.json")), "\n", "\r\n")
	result, err := LoadFile(context.Background(), writeTemp(t, "trivy.json", content), "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 4 || result.Coverage["source_type"] != "scanner:trivy" ||
		result.Coverage["complete"] != true || result.Coverage["records"] != 4 {
		t.Errorf("unexpected load result: %d findings, coverage %v", len(result.Findings), result.Coverage)
	}
}

func TestLoadForcedFormat(t *testing.T) {
	path := writeTemp(t, "osv.json", `{"results": []}`)
	result, err := LoadFile(context.Background(), path, "osv", nil, nil)
	if err != nil || len(result.Findings) != 0 || result.Coverage["source_type"] != "scanner:osv" {
		t.Errorf("forced osv: %v %v", result.Coverage, err)
	}
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
