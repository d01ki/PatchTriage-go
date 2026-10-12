package pipeline

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/d01ki/PatchTriage-go/data"
	"github.com/d01ki/PatchTriage-go/internal/enrich"
	"github.com/d01ki/PatchTriage-go/internal/ingest"
	"github.com/d01ki/PatchTriage-go/internal/model"
)

var timeKeys = map[string]bool{"enriched_at": true, "detected_at": true, "first_seen": true}

// normalize mirrors gen_golden.py: decode generically and blank timestamps.
func normalize(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, item := range x {
			if timeKeys[k] && item != nil {
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

// diffJSON reports the first differing path between two decoded values.
func diffJSON(path string, got, want any) string {
	switch w := want.(type) {
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			return fmt.Sprintf("%s: got %T, want object", path, got)
		}
		keys := map[string]bool{}
		for k := range w {
			keys[k] = true
		}
		for k := range g {
			keys[k] = true
		}
		var sorted []string
		for k := range keys {
			sorted = append(sorted, k)
		}
		sort.Strings(sorted)
		for _, k := range sorted {
			if d := diffJSON(path+"."+k, g[k], w[k]); d != "" {
				return d
			}
		}
		return ""
	case []any:
		g, ok := got.([]any)
		if !ok || len(g) != len(w) {
			return fmt.Sprintf("%s: got %v, want %v", path, got, want)
		}
		for i := range w {
			if d := diffJSON(fmt.Sprintf("%s[%d]", path, i), g[i], w[i]); d != "" {
				return d
			}
		}
		return ""
	}
	if !reflect.DeepEqual(got, want) {
		return fmt.Sprintf("%s: got %#v, want %#v", path, got, want)
	}
	return ""
}

func fakeOSV(t *testing.T) *ingest.OSVClient {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/osv_responses.json")
	if err != nil {
		t.Fatal(err)
	}
	var responses struct {
		Queries map[string][]string        `json:"queries"`
		Vulns   map[string]json.RawMessage `json:"vulns"`
	}
	_ = json.Unmarshal(raw, &responses)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/querybatch" {
			var body struct {
				Queries []struct {
					Package map[string]string `json:"package"`
				} `json:"queries"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			var results []map[string]any
			for _, q := range body.Queries {
				var vulns []map[string]string
				for _, id := range responses.Queries[q.Package["purl"]] {
					vulns = append(vulns, map[string]string{"id": id})
				}
				results = append(results, map[string]any{"vulns": vulns})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
			return
		}
		if record, ok := responses.Vulns[strings.TrimPrefix(r.URL.Path, "/v1/vulns/")]; ok {
			_, _ = w.Write(record)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)
	return &ingest.OSVClient{HTTP: server.Client(), BaseURL: server.URL, CacheDir: t.TempDir()}
}

// offlineEnrich points every provider at a server that fails the test.
func offlineEnrich(t *testing.T, cacheDir string) enrich.Options {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected network call %s", r.URL)
		http.Error(w, "offline", http.StatusTeapot)
	}))
	t.Cleanup(server.Close)
	return enrich.Options{UseNVD: true, UseVulnrichment: true, CacheDir: cacheDir, HTTP: server.Client(),
		URLs: enrich.Endpoints{EPSS: server.URL, KEV: server.URL, NVD: server.URL, CVERecord: server.URL}}
}

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

func TestAssessMatchesGolden(t *testing.T) {
	snapshot, err := enrich.DemoSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	target := model.NewAsset("")
	target.Kind, target.SystemExposure, target.MissionImpact = "host", "open", "mission_failure"
	target.SafetyImpact, target.PubliclyExposed, target.BOD2604Applicability = "catastrophic", "yes", "voluntary"
	trivy, grype := embedded(t, "fixtures/trivy_sample.json"), embedded(t, "fixtures/grype_sample.json")
	cases := map[string]func() ([]string, Options){
		"trivy": func() ([]string, Options) { return []string{trivy}, Options{} },
		"grype": func() ([]string, Options) { return []string{grype}, Options{} },
		"trivy_grype_inventory": func() ([]string, Options) {
			return []string{trivy, grype}, Options{Inventory: embedded(t, "demo_assets.yaml")}
		},
		"trivy_context":  func() ([]string, Options) { return []string{trivy}, Options{Asset: &target} },
		"osv_scanner":    func() ([]string, Options) { return []string{"../../testdata/osv_scanner_sample.json"}, Options{} },
		"sbom_cyclonedx": func() ([]string, Options) { return []string{"../../testdata/sbom_cyclonedx.json"}, Options{} },
		"sbom_spdx":      func() ([]string, Options) { return []string{"../../testdata/sbom_spdx.json"}, Options{} },
		"demo": func() ([]string, Options) {
			dir := t.TempDir()
			if err := enrich.SeedDemoCache(dir); err != nil {
				t.Fatal(err)
			}
			return []string{trivy, grype}, Options{Inventory: embedded(t, "demo_assets.yaml"),
				ProviderStatus: "complete", Enrich: offlineEnrich(t, dir)}
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			files, o := build()
			if name != "demo" {
				o.Snapshot, o.ProviderStatus = &snapshot, "provider_reported"
			}
			osv := fakeOSV(t)
			o.OSV = osv
			result, err := Assess(t.Context(), files, o)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(ReportJSON(result))
			if err != nil {
				t.Fatal(err)
			}
			raw = []byte(strings.ReplaceAll(string(raw), osv.BaseURL, "https://api.osv.dev"))
			var got, want any
			_ = json.Unmarshal(raw, &got)
			expected, err := os.ReadFile("../../testdata/golden/" + name + ".json")
			if err != nil {
				t.Fatal(err)
			}
			_ = json.Unmarshal(expected, &want)
			if d := diffJSON("$", normalize(got), want); d != "" {
				t.Errorf("differs from Python: %s", d)
			}
		})
	}
}

func TestAssessDemoOutcomes(t *testing.T) {
	dir := t.TempDir()
	if err := enrich.SeedDemoCache(dir); err != nil {
		t.Fatal(err)
	}
	result, err := Assess(t.Context(), []string{embedded(t, "fixtures/trivy_sample.json"), embedded(t, "fixtures/grype_sample.json")},
		Options{Inventory: embedded(t, "demo_assets.yaml"), ProviderStatus: "complete", Enrich: offlineEnrich(t, dir)})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"CVE-2022-22965": "immediate", "CVE-2023-4911": "out_of_cycle",
		"CVE-2024-3094": "scheduled", "CVE-2021-23337": "scheduled"}
	for _, f := range result.Findings {
		if f.Triage.SSVC.Decision != want[f.VulnID] {
			t.Errorf("%s = %s, want %s", f.VulnID, f.Triage.SSVC.Decision, want[f.VulnID])
		}
	}
	if len(result.Findings) != 4 || result.Coverage["status"] != "complete" {
		t.Errorf("findings %d, coverage %v", len(result.Findings), result.Coverage)
	}
}

func TestAssessLimitAppliesAfterSSVC(t *testing.T) {
	snapshot, _ := enrich.DemoSnapshot()
	target := model.NewAsset("")
	target.SystemExposure, target.MissionImpact, target.SafetyImpact = "open", "mef_failure", "critical"
	result, err := Assess(t.Context(), []string{embedded(t, "fixtures/trivy_sample.json")},
		Options{Snapshot: &snapshot, Asset: &target, Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	// xz-utils carries the highest CVSS (10.0) but the KEV Spring4Shell finding is the most urgent.
	if len(result.Subset) != 1 || result.Subset[0].VulnID != "CVE-2022-22965" || len(result.Findings) != 4 {
		t.Errorf("subset = %v", result.Subset)
	}
	for _, f := range result.Findings {
		if f.Triage == nil || f.Triage.BOD2604 == nil {
			t.Errorf("%s: every finding keeps its SSVC and policy record", f.VulnID)
		}
	}
}

func TestAssessAppliesAnalystOverrides(t *testing.T) {
	snapshot, _ := enrich.DemoSnapshot()
	first, err := Assess(t.Context(), []string{embedded(t, "fixtures/trivy_sample.json")}, Options{Snapshot: &snapshot})
	if err != nil {
		t.Fatal(err)
	}
	key := first.Findings[0].Key
	result, _ := Assess(t.Context(), []string{embedded(t, "fixtures/trivy_sample.json")}, Options{Snapshot: &snapshot,
		SSVCOverrides: map[string]map[string]string{key: {"automatable": "no", "mission_impact": "ignored"}}})
	for _, f := range result.Findings {
		if f.Key == key && (f.SSVCInputs["automatable"] != "no" || len(f.SSVCInputs) != 1 || f.Triage.SSVC.Automatable.Inferred) {
			t.Errorf("override = %v / %+v", f.SSVCInputs, f.Triage.SSVC.Automatable)
		}
	}
}

func coverageFixture(total, checked, skipped int, names, queried []string) model.Coverage {
	return model.Coverage{"source_type": "sbom:osv", "total_components": total, "queryable_components": checked,
		"queried_components": checked, "unqueryable_components": skipped, "unqueryable_names": names,
		"queried_ecosystems": queried, "unqueryable_ecosystems": []string{}, "errors": []string{}}
}

func TestResultMessageStates(t *testing.T) {
	msg := func(coverage model.Coverage) string { return ResultMessage(0, 0, true, "provider_reported", coverage) }
	m := msg(coverageFixture(21, 10, 11, []string{"fastapi", "pydantic", "httpx"}, nil))
	for _, want := range []string{"10 of 21", "11 component(s) could not be checked", "fastapi", "lockfile"} {
		if !strings.Contains(m, want) {
			t.Errorf("missing %q in %q", want, m)
		}
	}
	var names []string
	for i := 0; i < 12; i++ {
		names = append(names, fmt.Sprintf("pkg%d", i))
	}
	if m := msg(coverageFixture(21, 10, 12, names, nil)); !strings.Contains(m, "pkg0") || strings.Contains(m, "pkg11") || !strings.Contains(m, "and 7 more") {
		t.Errorf("truncation: %q", m)
	}
	if m := msg(coverageFixture(21, 10, 11, []string{"fastapi"}, []string{"githubactions"})); !strings.Contains(m, "no application dependency was actually assessed") {
		t.Errorf("CI-only: %q", m)
	}
	if m := msg(coverageFixture(21, 10, 11, []string{"fastapi"}, []string{"githubactions", "PyPI"})); strings.Contains(m, "no application dependency") {
		t.Errorf("real deps checked: %q", m)
	}
	if m := ResultMessage(0, 0, false, "complete", coverageFixture(5, 5, 0, nil, nil)); m != "The attached evidence reported no vulnerability findings." {
		t.Errorf("clean: %q", m)
	}
	if m := msg(model.Coverage{}); !strings.Contains(m, "not independently verified") {
		t.Errorf("provider reported: %q", m)
	}
	if m := ResultMessage(1, 1, false, "complete", coverageFixture(21, 10, 11, nil, nil)); m != "" {
		t.Errorf("findings present: %q", m)
	}
	inferred := coverageFixture(14, 11, 3, []string{"actions/checkout"}, []string{"githubactions", "pypi"})
	inferred["inferred_components"] = 9
	if m := msg(inferred); !strings.Contains(m, "11 of 14") || !strings.Contains(m, "9 component(s) had only a declared constraint") ||
		!strings.Contains(m, "oldest a lower-bounded range permits") || strings.Contains(m, "no application dependency") {
		t.Errorf("inferred: %q", m)
	}
	all := coverageFixture(9, 9, 0, nil, nil)
	all["inferred_components"] = 9
	if m := msg(all); !strings.Contains(m, "registry release chosen") || !strings.Contains(m, "lockfile") {
		t.Errorf("all inferred: %q", m)
	}
	// Values decoded from stored JSON (float64, []any) read the same.
	var decoded model.Coverage
	raw, _ := json.Marshal(coverageFixture(21, 10, 11, []string{"fastapi"}, nil))
	_ = json.Unmarshal(raw, &decoded)
	if m := msg(decoded); !strings.Contains(m, "10 of 21") || !strings.Contains(m, "fastapi") {
		t.Errorf("decoded coverage: %q", m)
	}
}

func TestFileCoverageMergeNeverHidesAnIncompleteFile(t *testing.T) {
	merged := MergeFileCoverage([]model.Coverage{
		{"source_type": "scanner:trivy", "complete": true, "records": 4, "errors": []string{}},
		{"source_type": "sbom:osv", "complete": false, "total_components": 3, "queried_components": 1,
			"unqueryable_components": 2, "unqueryable_names": []string{"a", "b"}, "errors": []string{"timeout"}},
	})
	if merged["complete"] != false || merged["total_components"] != 3 || fmt.Sprint(merged["unqueryable_names"]) != "[a b]" ||
		fmt.Sprint(merged["errors"]) != "[timeout]" || merged["source_type"] != "scanner:trivy+sbom:osv" {
		t.Errorf("merged = %v", merged)
	}
	single := model.Coverage{"source_type": "scanner:grype", "complete": true}
	if got := MergeFileCoverage([]model.Coverage{single}); !reflect.DeepEqual(got, single) {
		t.Errorf("single = %v", got)
	}
	combined := CombineCoverage(model.Coverage{"complete": false, "warnings": "x"}, model.Coverage{"complete": true}, "")
	if combined["status"] != "incomplete" || combined["complete"] != false || combined["warnings"] != "x" {
		t.Errorf("combined = %v", combined)
	}
	if c := CombineCoverage(model.Coverage{}, model.Coverage{"complete": true}, "partial"); c["status"] != "partial" {
		t.Errorf("provider status wins: %v", c)
	}
}
