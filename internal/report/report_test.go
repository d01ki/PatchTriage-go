package report

import (
	"html"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/d01ki/PatchTriage-go/data"
	"github.com/d01ki/PatchTriage-go/internal/decision"
	"github.com/d01ki/PatchTriage-go/internal/enrich"
	"github.com/d01ki/PatchTriage-go/internal/model"
	"github.com/d01ki/PatchTriage-go/internal/pipeline"
)

func embedded(t *testing.T, name string) string {
	t.Helper()
	raw, err := data.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), filepath.Base(name))
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func demo(t *testing.T) *pipeline.Assessment {
	t.Helper()
	dir := t.TempDir()
	if err := enrich.SeedDemoCache(dir); err != nil {
		t.Fatal(err)
	}
	result, err := pipeline.Assess(t.Context(),
		[]string{embedded(t, "fixtures/trivy_sample.json"), embedded(t, "fixtures/grype_sample.json")},
		pipeline.Options{Inventory: embedded(t, "demo_assets.yaml"), ProviderStatus: "complete",
			Enrich: enrich.Options{UseNVD: true, UseVulnrichment: true, CacheDir: dir,
				URLs: enrich.Endpoints{EPSS: "http://127.0.0.1:1", KEV: "http://127.0.0.1:1", NVD: "http://127.0.0.1:1", CVERecord: "http://127.0.0.1:1"}}})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func render(t *testing.T, findings []*model.Finding, actions []pipeline.Action, rows []pipeline.EvalRow, o HTMLOptions) string {
	t.Helper()
	out, err := RenderHTML(findings, actions, rows, o)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

var (
	styleBlock = regexp.MustCompile(`(?s)<style>.*?</style>`)
	tag        = regexp.MustCompile(`<[^>]*>`)
	spaces     = regexp.MustCompile(`\s+`)
	generated  = regexp.MustCompile(`generated \d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC`)
)

// visibleText reduces a page to what a reader sees.
func visibleText(page string) string {
	text := tag.ReplaceAllString(styleBlock.ReplaceAllString(page, " "), " ")
	text = generated.ReplaceAllString(html.UnescapeString(text), "generated <time>")
	return strings.TrimSpace(spaces.ReplaceAllString(text, " "))
}

func TestRenderHTMLDemoMatchesPythonText(t *testing.T) {
	result := demo(t)
	got := render(t, result.Subset, result.Actions, result.EvalRows, HTMLOptions{Coverage: result.Coverage})
	want, err := os.ReadFile("../../testdata/golden/demo.html")
	if err != nil {
		t.Fatal(err)
	}
	g, w := visibleText(got), visibleText(string(want))
	if g != w {
		for i := range min(len(g), len(w)) {
			if g[i] != w[i] {
				t.Fatalf("visible text differs from Python at %d:\n got …%s…\nwant …%s…", i, g[max(0, i-80):min(len(g), i+80)], w[max(0, i-80):min(len(w), i+80)])
			}
		}
		t.Fatalf("visible text length differs: got %d, want %d", len(g), len(w))
	}
}

func TestRenderHTMLSelfContained(t *testing.T) {
	result := demo(t)
	page := render(t, result.Subset, result.Actions, result.EvalRows, HTMLOptions{Coverage: result.Coverage})
	for _, banned := range []string{"<script", "<link", "cdn", "@import"} {
		if strings.Contains(strings.ToLower(page), banned) {
			t.Errorf("report must stay self-contained, found %q", banned)
		}
	}
	for _, want := range []string{"<!doctype html>", "CVE-2023-4911", "Remediation plan", "Why Immediate", ">Immediate<",
		`class="evidence"`, "smaller first-pass queue", "environment context decides", "Decision quality",
		"CISA BOD 26-04 response policy"} {
		if !strings.Contains(page, want) {
			t.Errorf("missing %q", want)
		}
	}
	for _, code := range []string{"P1", "P2", "P3", "P4"} {
		if strings.Contains(page, code) {
			t.Errorf("internal priority code %s leaked into the report", code)
		}
	}
}

func TestHTMLEscapesUntrustedText(t *testing.T) {
	asset := model.NewAsset(`<script>alert(1)</script>`)
	f := &model.Finding{Key: "k", VulnID: `CVE-2024-0001"><img src=x onerror=alert(1)>`, Asset: asset,
		Package: model.Package{Name: "<b>pkg</b>", Version: "1.0"},
		Enrichment: model.Enrichment{VendorAdvisories: []model.VendorAdvisory{{Source: "ghsa", AdvisoryID: "GHSA-x",
			URL: "javascript:alert(1)", Title: "<i>t</i>"}}}}
	f.Triage = decision.Triage(f)
	page := render(t, []*model.Finding{f}, pipeline.BuildPlan([]*model.Finding{f}), nil, HTMLOptions{Title: "<x>"})
	for _, raw := range []string{"<script>alert(1)", "<img src=x", "<b>pkg</b>", "<i>t</i>", `href="javascript:`, "<title><x>"} {
		if strings.Contains(page, raw) {
			t.Errorf("unescaped untrusted text %q in report", raw)
		}
	}
}

func TestRenderHTMLStates(t *testing.T) {
	empty := render(t, nil, nil, nil, HTMLOptions{})
	if !strings.Contains(empty, "No vulnerability records were reported") || !strings.Contains(empty, "No SSVC assessment was required") ||
		strings.Contains(empty, "Outcome at a top-") || strings.Contains(empty, "Decision quality") {
		t.Error("empty input report")
	}
	incomplete := render(t, nil, nil, nil, HTMLOptions{
		Coverage: model.Coverage{"status": "incomplete", "complete": false, "total_components": 2, "failed_components": 2,
			"errors": []string{"OSV query failed"}},
		CoverageWarnings: []string{"Provider scope could not be verified."}})
	for _, want := range []string{"evidence coverage is limited", "Status: incomplete", "OSV query failed", "Provider scope could not be verified"} {
		if !strings.Contains(incomplete, want) {
			t.Errorf("incomplete coverage report lacks %q", want)
		}
	}
	ciOnly := render(t, nil, nil, nil, HTMLOptions{Coverage: model.Coverage{"status": "provider_reported", "total_components": 21,
		"queried_components": 10, "unqueryable_names": []string{"fastapi", "pydantic"}, "queried_ecosystems": []string{"githubactions"}}})
	if !strings.Contains(ciOnly, "Not checked: fastapi, pydantic") || !strings.Contains(ciOnly, "no application dependency was assessed") {
		t.Error("skipped components and the CI-only boundary must be named")
	}
	result := demo(t)
	result.Subset[0].Enrichment.VendorSourcesChecked = []string{"debian"}
	result.Subset[0].Enrichment.VendorAdvisories = []model.VendorAdvisory{{Source: "debian", AdvisoryID: result.Subset[0].VulnID,
		Title: "Debian tracker record", URL: "https://security-tracker.debian.org/tracker/" + result.Subset[0].VulnID,
		Products: []string{"libc6 (bookworm: resolved)"}, FixedVersions: []string{"libc6 bookworm: 2.36-9+deb12u3"}}}
	vendor := visibleText(render(t, result.Subset, result.Actions, result.EvalRows, HTMLOptions{}))
	for _, want := range []string{"Official vendor advisories", "DEBIAN", "2.36-9+deb12u3", "· DEBIAN ·"} {
		if !strings.Contains(vendor, want) {
			t.Errorf("vendor evidence report lacks %q", want)
		}
	}
}
