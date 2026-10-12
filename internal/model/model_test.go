package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNormalizeEcosystem(t *testing.T) {
	cases := map[string]string{
		"PyPI": "pypi", "python": "pypi", "GitHub Actions": "githubactions",
		"go": "golang", "java-archive": "maven", "jar": "maven",
		"unknown": "", "apk": "alpine", "crates.io": "crates.io", "": "",
	}
	for in, want := range cases {
		if got := NormalizeEcosystem(in); got != want {
			t.Errorf("NormalizeEcosystem(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParsePurl(t *testing.T) {
	cases := []struct{ in, typ, ns, name, version string }{
		{"pkg:npm/%40babel/core@7.0.0", "npm", "@babel", "core", "7.0.0"},
		{"pkg:maven/org.springframework/spring-beans@5.3.17?type=jar", "maven", "org.springframework", "spring-beans", "5.3.17"},
		{"pkg:npm/@scope/x", "npm", "@scope", "x", ""},
		{"PKG:PyPI/django@3.2.0#sub", "pypi", "", "django", "3.2.0"},
		{"not-a-purl", "", "", "", ""},
		{"pkg:npm", "", "", "", ""},
	}
	for _, c := range cases {
		typ, ns, name, version := ParsePurl(c.in)
		if typ != c.typ || ns != c.ns || name != c.name || version != c.version {
			t.Errorf("ParsePurl(%q) = (%q,%q,%q,%q), want (%q,%q,%q,%q)",
				c.in, typ, ns, name, version, c.typ, c.ns, c.name, c.version)
		}
	}
}

func TestParseSeverity(t *testing.T) {
	cases := map[string]Severity{
		"Moderate": SeverityMedium, "important": SeverityHigh, "": SeverityUnknown,
		"bogus": SeverityUnknown, " CRITICAL ": SeverityCritical,
	}
	for in, want := range cases {
		if got := ParseSeverity(in); got != want {
			t.Errorf("ParseSeverity(%q) = %q, want %q", in, got, want)
		}
	}
	if SeverityRank(SeverityCritical) != 4 || SeverityRank(SeverityUnknown) != 0 {
		t.Error("severity ranks differ from dedup._SEV_ORDER")
	}
}

func TestAssetNormalize(t *testing.T) {
	a := NewAsset("web")
	a.SystemExposure = "Open"
	a.MissionImpact = "mef-failure"
	a.PubliclyExposed = ""
	if err := a.Normalize(); err != nil {
		t.Fatal(err)
	}
	if a.SystemExposure != "open" || a.MissionImpact != "mef_failure" || a.PubliclyExposed != "unknown" {
		t.Errorf("unexpected normalization: %+v", a)
	}
	bad := NewAsset("web")
	bad.SystemExposure = "public"
	err := bad.Normalize()
	if err == nil || !strings.Contains(err.Error(), "system_exposure must be one of:") {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestFindingJSONShape(t *testing.T) {
	f := Finding{Key: "k", VulnID: "CVE-1", Package: Package{Name: "p"}, Asset: NewAsset("a")}
	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{`"cvss_score":null`, `"aliases":[]`, `"triage":null`,
		`"internet_exposed":null`, `"fixed_version_candidates":[]`, `"retrieval_status":{}`,
		`"vendor_advisories":[]`, `"ssvc_inputs":{}`, `"severity":"unknown"`} {
		if !strings.Contains(s, want) {
			t.Errorf("marshalled finding lacks %s:\n%s", want, s)
		}
	}
}
