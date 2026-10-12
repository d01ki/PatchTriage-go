package ingest

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/d01ki/PatchTriage-go/internal/model"
)

type rawOpt func(*model.RawFinding)

func rawFinding(id string, opts ...rawOpt) model.RawFinding {
	r := model.RawFinding{VulnID: id, SourceScanner: "scanner",
		Package: model.Package{Name: "widget", Version: "1.0", Ecosystem: "npm", FixedVersion: "2.0"},
		Asset:   model.NewAsset("asset-1"), Severity: model.SeverityHigh}
	for _, opt := range opts {
		opt(&r)
	}
	return r
}

func eco(e string) rawOpt        { return func(r *model.RawFinding) { r.Package.Ecosystem = e } }
func ver(v string) rawOpt        { return func(r *model.RawFinding) { r.Package.Version = v } }
func purl(p string) rawOpt       { return func(r *model.RawFinding) { r.Package.Purl = p } }
func fixed(f string) rawOpt      { return func(r *model.RawFinding) { r.Package.FixedVersion = f } }
func scanner(s string) rawOpt    { return func(r *model.RawFinding) { r.SourceScanner = s } }
func aliases(a ...string) rawOpt { return func(r *model.RawFinding) { r.Aliases = a } }
func cvss(v float64) rawOpt      { return func(r *model.RawFinding) { r.CVSSScore = &v } }
func severity(s model.Severity) rawOpt {
	return func(r *model.RawFinding) { r.Severity = s }
}

func TestDedupKeepsEcosystemAndInstalledVersionInIdentity(t *testing.T) {
	findings := Dedup([]model.RawFinding{
		rawFinding("CVE-2026-0001", eco("debian")),
		rawFinding("CVE-2026-0001", eco("deb"), scanner("other")),
		rawFinding("CVE-2026-0001", eco("debian"), ver("1.1")),
		rawFinding("CVE-2026-0001", eco("npm")),
	})
	if len(findings) != 3 {
		t.Fatalf("got %d findings, want 3", len(findings))
	}
	for _, f := range findings {
		if f.Package.Ecosystem == "debian" && f.Package.Version == "1.0" &&
			strings.Join(f.ReportedBy, ",") != "other,scanner" {
			t.Errorf("reported_by = %v", f.ReportedBy)
		}
	}
}

func TestDedupEmptyEcosystemDoesNotBridge(t *testing.T) {
	findings := Dedup([]model.RawFinding{
		rawFinding("CVE-2026-0002", eco("maven"), purl("pkg:maven/org.alpha/widget@1.0"), scanner("alpha")),
		rawFinding("CVE-2026-0002", eco("maven"), purl("pkg:maven/org.beta/widget@1.0"), scanner("beta")),
		rawFinding("CVE-2026-0002", eco("java"), scanner("unknown")),
	})
	if len(findings) != 3 {
		t.Errorf("ambiguous namespace bridged: %d findings, want 3", len(findings))
	}
	one := Dedup([]model.RawFinding{
		rawFinding("CVE-2026-0003", eco("maven"), purl("pkg:maven/org.alpha/widget@1.0"), scanner("purl")),
		rawFinding("CVE-2026-0003", eco("java"), scanner("no-purl")),
	})
	if len(one) != 1 || strings.Join(one[0].ReportedBy, ",") != "no-purl,purl" {
		t.Errorf("unambiguous namespace not filled: %+v", one)
	}
}

func TestDedupMergesCVEAndGHSAAcrossScanners(t *testing.T) {
	findings := Dedup([]model.RawFinding{
		rawFinding("CVE-2023-1", scanner("trivy"), severity(model.SeverityMedium), cvss(5.0)),
		rawFinding("GHSA-x", aliases("CVE-2023-1"), scanner("grype"), severity(model.SeverityCritical), cvss(9.1)),
	})
	if len(findings) != 1 {
		t.Fatalf("got %d findings", len(findings))
	}
	f := findings[0]
	if f.VulnID != "CVE-2023-1" || strings.Join(f.Aliases, ",") != "GHSA-x" || f.Severity != model.SeverityCritical ||
		*f.CVSSScore != 9.1 || strings.Join(f.ReportedBy, ",") != "grype,trivy" {
		t.Errorf("merged = %+v", f)
	}
	// A GHSA-only record links to a CVE seen elsewhere through the alias map.
	linked := Dedup([]model.RawFinding{
		rawFinding("GHSA-y", aliases("CVE-2023-9")),
		rawFinding("GHSA-y", scanner("other")),
	})
	if len(linked) != 1 || linked[0].VulnID != "CVE-2023-9" {
		t.Errorf("alias link failed: %+v", linked)
	}
}

func TestDedupFixedCandidatesRetained(t *testing.T) {
	findings := Dedup([]model.RawFinding{
		rawFinding("CVE-2026-0012", fixed("9.9"), scanner("first")),
		rawFinding("CVE-2026-0012", fixed("10.0"), scanner("second")),
	})
	if got := strings.Join(findings[0].Package.FixedVersionCandidates, ","); got != "10.0,9.9" {
		t.Errorf("candidates = %s", got)
	}
	if findings[0].Package.FixedVersion != "9.9" {
		t.Errorf("fixed = %s, want first scanner's value", findings[0].Package.FixedVersion)
	}
}

func TestDedupOrdersBySeverityThenCVSS(t *testing.T) {
	findings := Dedup([]model.RawFinding{
		rawFinding("CVE-1", severity(model.SeverityUnknown)),
		rawFinding("CVE-2", severity(model.SeverityNegligible)),
		rawFinding("CVE-3", severity(model.SeverityHigh), cvss(5)),
		rawFinding("CVE-4", severity(model.SeverityHigh), cvss(8)),
	})
	var order []string
	for _, f := range findings {
		order = append(order, f.VulnID)
	}
	if strings.Join(order, ",") != "CVE-4,CVE-3,CVE-2,CVE-1" {
		t.Errorf("order = %v", order)
	}
}

func TestDedupMatchesGoldenTrivyGrype(t *testing.T) {
	trivy, _ := ParseScanner(fixture(t, "trivy_sample.json"), "trivy", nil)
	grype, _ := ParseScanner(fixture(t, "grype_sample.json"), "grype", nil)
	findings := Dedup(append(trivy, grype...))
	raw, err := os.ReadFile("../../testdata/golden/trivy_grype_inventory.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden struct {
		Findings []struct {
			Key        string        `json:"key"`
			Package    model.Package `json:"package"`
			ReportedBy []string      `json:"reported_by"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}
	var got, want []string
	for _, f := range findings {
		got = append(got, f.Key+" "+f.Package.FixedVersion+" "+strings.Join(f.ReportedBy, ","))
	}
	for _, f := range golden.Findings {
		want = append(want, f.Key+" "+f.Package.FixedVersion+" "+strings.Join(f.ReportedBy, ","))
	}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("dedup differs from Python:\n got: %v\nwant: %v", got, want)
	}
}
