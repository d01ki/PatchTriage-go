package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/d01ki/PatchTriage-go/internal/ai"
	"github.com/d01ki/PatchTriage-go/internal/pipeline"
	"github.com/d01ki/PatchTriage-go/internal/repository"
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

func TestParseRunAIOptions(t *testing.T) {
	t.Setenv("PATCHTRIAGE_CONFIG_DIR", t.TempDir())
	cfg, err := parseRun([]string{"scan.json", "--triage", "cascade", "--provider", "ollama", "--ai-base-url",
		"http://localhost:11434/v1", "--model", "small", "--escalation-model", "big", "--jobs", "8"})
	want := pipeline.TriageOptions{Backend: "cascade", Model: "small", EscalationModel: "big", Provider: "ollama",
		BaseURL: "http://localhost:11434/v1", Jobs: 8}
	if err != nil || cfg.options.Triage != want {
		t.Errorf("triage options = %+v, %v", cfg.options.Triage, err)
	}
	if cfg, _ := parseRun([]string{"scan.json"}); cfg.options.Triage.Backend != "rules" {
		t.Errorf("default backend = %q", cfg.options.Triage.Backend)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"run", "scan.json", "--triage", "magic"}, &stdout, &stderr); code == 0 ||
		!strings.Contains(stderr.String(), "Unknown triage backend: magic") {
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

func TestCLIServeRejectsBadFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"serve", "--port", "not-a-port"}, &stdout, &stderr); code != 1 {
		t.Errorf("exit %d for an invalid port", code)
	}
	if code := run([]string{"serve", "--port", "70000", "--no-browser"}, &stdout, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "port") {
		t.Errorf("exit %d, stderr %q", code, stderr.String())
	}
}

func TestRemediateWithoutArgumentsRunsGuidedLocalWorkflow(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	tmp := t.TempDir()
	repo := filepath.Join(tmp, "source")
	_ = os.Mkdir(repo, 0o755)
	for _, args := range [][]string{{"init", "--quiet"}, {"config", "user.name", "T"}, {"config", "user.email", "t@example.invalid"}} {
		if out, err := exec.Command("git", append([]string{"-C", repo}, args...)...).CombinedOutput(); err != nil {
			t.Fatal(err, string(out))
		}
	}
	_ = os.WriteFile(filepath.Join(repo, "package.json"), []byte(`{"dependencies":{"lodash":"4.17.20"}}`+"\n"), 0o644)
	for _, args := range [][]string{{"add", "."}, {"commit", "--quiet", "-m", "fixture"}} {
		if out, err := exec.Command("git", append([]string{"-C", repo}, args...)...).CombinedOutput(); err != nil {
			t.Fatal(err, string(out))
		}
	}
	report := filepath.Join(tmp, "report.json")
	_ = os.WriteFile(report, []byte(`{"actions": [{"action_id": "upgrade:repo:npm::lodash:4.17.20", "kind": "upgrade", "asset": "repo",
		"summary": "Upgrade lodash to 4.17.21", "package": "lodash", "ecosystem": "npm", "installed_version": "4.17.20",
		"target_version": "4.17.21", "cves": ["CVE-2021-23337"], "top_priority": "P2"}]}`), 0o644)
	stdin = strings.NewReader(strings.Join([]string{report, repo, "1", "", "", "y", ""}, "\n"))
	defer func() { stdin = os.Stdin }()
	var stdout, stderr bytes.Buffer
	if code := run([]string{"remediate", "--no-lock", "--no-scan"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s %s", code, stdout.String(), stderr.String())
	}
	for _, want := range []string{"Confirmed dependency upgrades", "Execution plan", "Local review commands"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, stdout.String())
		}
	}
	output := filepath.Join(tmp, "source-patchtriage-remediation")
	patched, _ := os.ReadFile(filepath.Join(output, "workspace", "package.json"))
	if _, err := os.Stat(filepath.Join(output, "remediation.patch")); err != nil || !strings.Contains(string(patched), `"lodash": "4.17.21"`) {
		t.Errorf("patch %v, package.json %s", err, patched)
	}
}

// isolateConfig points the saved configuration at a temp dir and clears
// every key the configuration can export, restoring them afterwards.
func isolateConfig(t *testing.T) string {
	dir := t.TempDir()
	t.Setenv("PATCHTRIAGE_CONFIG_DIR", dir)
	for _, key := range append(ai.EnvKeys, "GH_TOKEN") {
		t.Setenv(key, "")
	}
	return dir
}

func feed(t *testing.T, answers ...string) {
	stdin = strings.NewReader(strings.Join(answers, "\n") + "\n")
	t.Cleanup(func() { stdin = os.Stdin })
}

func TestPastedPathsAreNormalized(t *testing.T) {
	if got := normalizeInputPattern(`"scans/my sbom.json"`, false, false); got != "scans/my sbom.json" {
		t.Errorf("quotes: %q", got)
	}
	windows := `C:\Users\analyst\Downloads\aibom.cdx.json`
	if got := normalizeInputPattern(`"`+windows+`"`, true, false); got != "/mnt/c/Users/analyst/Downloads/aibom.cdx.json" {
		t.Errorf("wsl: %q", got)
	}
	// A container cannot see the host path, so it is not misrepresented as visible.
	if got := normalizeInputPattern(windows, true, true); got != windows {
		t.Errorf("container: %q", got)
	}
}

func TestSetupValidatesAndSavesProviderChoice(t *testing.T) {
	dir := isolateConfig(t)
	var validated []string
	original := validateKey
	t.Cleanup(func() { validateKey = original })
	validateKey = func(_ context.Context, provider, key string) (bool, string) {
		validated = append(validated, provider+":"+key)
		if key == "bad" {
			return false, "authentication failed (401) - check the key"
		}
		return true, "key is valid"
	}
	// provider, bad key, retry, good key, NVD key, no GitHub token, backend
	feed(t, "anthropic", "bad", "y", "sk-ant-good-key-123", "nvd-key", "", "")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"setup"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s %s", code, stdout.String(), stderr.String())
	}
	if !reflect.DeepEqual(validated, []string{"anthropic:bad", "anthropic:sk-ant-good-key-123"}) {
		t.Errorf("validated %v", validated)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "config.json"))
	var cfg map[string]any
	_ = json.Unmarshal(raw, &cfg)
	want := map[string]any{"PATCHTRIAGE_AI_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "sk-ant-good-key-123",
		"NVD_API_KEY": "nvd-key", "default_backend": "cascade"}
	if !reflect.DeepEqual(cfg, want) {
		t.Errorf("config %v", cfg)
	}
	if strings.Contains(stdout.String(), "sk-ant-good-key-123") {
		t.Error("the key was echoed back")
	}
}

func TestSetupWithoutKeyFallsBackToRules(t *testing.T) {
	dir := isolateConfig(t)
	feed(t, "openai-compatible", "", "", "", "")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"setup"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s %s", code, stdout.String(), stderr.String())
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "config.json"))
	var cfg map[string]any
	_ = json.Unmarshal(raw, &cfg)
	if !reflect.DeepEqual(cfg, map[string]any{"default_backend": "rules"}) {
		t.Errorf("config %v\n%s", cfg, stdout.String())
	}
}

func TestStartAcceptsARepositoryURLLikeTheGUI(t *testing.T) {
	dir := isolateConfig(t)
	_ = os.WriteFile(filepath.Join(dir, "config.json"), []byte("{}"), 0o600)
	var requested []string
	originalAcquire := acquireRepository
	t.Cleanup(func() { acquireRepository, assess = originalAcquire, pipeline.Assess })
	acquireRepository = func(_ context.Context, url string) (repository.Evidence, error) {
		requested = append(requested, url)
		if strings.Contains(url, "missing") {
			return repository.Evidence{}, &repository.Error{Status: 404, Message: "repository not found"}
		}
		return repository.Evidence{Content: `{"spdxVersion": "SPDX-2.3"}`, Format: "spdx", Provenance: map[string]any{
			"provider": "github", "repository": "acme/widgets", "coverage_status": "provider_reported",
			"warnings": []any{"Dependency Graph coverage boundary."}}}, nil
	}
	var content string
	var options pipeline.Options
	assess = func(_ context.Context, files []string, o pipeline.Options) (*pipeline.Assessment, error) {
		raw, _ := os.ReadFile(files[0])
		content, options = string(raw), o
		return &pipeline.Assessment{Coverage: map[string]any{}}, nil
	}
	html, output := filepath.Join(dir, "r.html"), filepath.Join(dir, "r.json")
	feed(t, "https://github.com/acme/missing", "https://github.com/acme/widgets",
		"", "open", "", "", "n", "n", // context
		"", "n", html, output, // backend, NVD, reports
		"n") // browser (not asked when headless)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"start"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "repository not found") ||
		!reflect.DeepEqual(requested, []string{"https://github.com/acme/missing", "https://github.com/acme/widgets"}) {
		t.Errorf("requested %v\n%s", requested, stdout.String())
	}
	if content != `{"spdxVersion": "SPDX-2.3"}` || options.ProviderStatus != "provider_reported" ||
		options.Asset == nil || options.Asset.Identifier != "acme/widgets" || options.Asset.Kind != "repository" ||
		options.Asset.SystemExposure != "open" || options.Triage.Backend != "rules" || options.Enrich.UseNVD {
		t.Errorf("content %q options %+v asset %+v", content, options, options.Asset)
	}
	report, _ := os.ReadFile(html)
	if !strings.Contains(string(report), "Dependency Graph coverage boundary.") {
		t.Error("the HTML report lacks the provider coverage warning")
	}
	if _, err := os.Stat(output); err != nil {
		t.Error(err)
	}
}
