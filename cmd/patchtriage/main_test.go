package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func normalize(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, item := range x {
			if (k == "enriched_at" || k == "detected_at" || k == "first_seen") && item != nil {
				x[k] = "<time>"
			} else {
				x[k] = normalize(item)
			}
		}
	case []any:
		for i := range x {
			x[i] = normalize(x[i])
		}
	}
	return v
}

func TestCLIDemoWritesReports(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := run([]string{"demo", "--html", filepath.Join(dir, "r.html"), "-o", filepath.Join(dir, "r.json")}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	raw, err := os.ReadFile(filepath.Join(dir, "r.json"))
	if err != nil {
		t.Fatal(err)
	}
	expected, _ := os.ReadFile("../../testdata/golden/demo.json")
	var got, want any
	_ = json.Unmarshal(raw, &got)
	_ = json.Unmarshal(expected, &want)
	if !reflect.DeepEqual(normalize(got), want) {
		t.Error("demo JSON differs from the Python golden report")
	}
	if html, err := os.ReadFile(filepath.Join(dir, "r.html")); err != nil || !strings.Contains(string(html), "Why Immediate") {
		t.Errorf("demo HTML missing or incomplete: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{"Immediate", "Upgrade org.springframework:spring-beans", "audit: 4/4", "HTML report:", "JSON report:"} {
		if !strings.Contains(out, want) {
			t.Errorf("console output lacks %q:\n%s", want, out)
		}
	}
}

func TestCLIRunRejectsAITriage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"run", "scan.json", "--triage", "ai"}, &stdout, &stderr); code == 0 ||
		!strings.Contains(stderr.String(), "rules") {
		t.Errorf("exit %d, stderr %q", code, stderr.String())
	}
}

func TestParseRunInterleavedFlagsAndContext(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "gh-token")
	cfg, err := parseRun([]string{"trivy.json", "--ssvc-exposure", "Open", "grype.json", "--html", "r.html", "-o", "r.json",
		"--bod2604", "voluntary", "--publicly-exposed", "yes", "--not-exposed", "--no-nvd", "--no-vendor-advisories", "--limit", "5"})
	if err != nil {
		t.Fatal(err)
	}
	o := cfg.options
	if strings.Join(cfg.files, ",") != "trivy.json,grype.json" || cfg.html != "r.html" || cfg.output != "r.json" ||
		o.Asset == nil || o.Asset.SystemExposure != "open" || o.Asset.BOD2604Applicability != "voluntary" ||
		o.Asset.PubliclyExposed != "yes" || o.Asset.InternetExposed == nil || *o.Asset.InternetExposed ||
		o.Asset.Kind != "host" || o.Asset.Identifier != "" || o.Enrich.UseNVD || !o.Enrich.UseVulnrichment ||
		o.Enrich.VendorSources != "" || o.Enrich.GitHubToken != "gh-token" || o.Limit != 5 || o.ProviderStatus != "provider_reported" {
		t.Errorf("config = %+v / asset %+v / enrich %+v", cfg, o.Asset, o.Enrich)
	}
	only, _ := parseRun([]string{"scan.json", "--ssvc-mission-impact", "mef-failure"})
	if only.options.Asset == nil || only.options.Asset.MissionImpact != "mef_failure" {
		t.Errorf("a single SSVC context flag must create the context override: %+v", only.options.Asset)
	}
	plain, _ := parseRun([]string{"scan.json"})
	if plain.options.Asset != nil || plain.options.Enrich.VendorSources != "auto" {
		t.Errorf("no context flags must leave the scanner asset untouched: %+v", plain.options)
	}
	if _, err := parseRun([]string{"scan.json", "--ssvc-exposure", "public"}); err == nil ||
		!strings.Contains(err.Error(), "system_exposure must be one of") {
		t.Errorf("invalid context err = %v", err)
	}
	if _, err := parseRun([]string{"--html", "r.html"}); err == nil {
		t.Error("run without evidence files must fail")
	}
}

func TestUnknownCommandShowsUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"bogus"}, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "usage") {
		t.Errorf("exit %d, stderr %q", code, stderr.String())
	}
}

func TestCLIVerify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "verification_report.json")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"verify", "--repeats", "3", "--output", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"official ssvc deployer table", "72", "PASS", "Input fingerprint:", "Decision fingerprint:"} {
		if !strings.Contains(out, want) {
			t.Errorf("verify output lacks %q:\n%s", want, out)
		}
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("report not written: %v", err)
	}
	if code := run([]string{"verify", "--repeats", "1", "--output", path}, &stdout, &stderr); code == 0 {
		t.Error("repeats below 2 must fail")
	}
}
