package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/d01ki/PatchTriage-go/internal/repository"
)

// demoTarget creates the GUI demo target exactly like POST /api/demo.
func demoTarget(t *testing.T, s *Store, ws string) Target {
	t.Helper()
	target, _, err := CreateDemoTarget(s, ws, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func diff(path string, got, want any) string {
	switch w := want.(type) {
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			return fmt.Sprintf("%s: got %T", path, got)
		}
		var keys []string
		for k := range w {
			keys = append(keys, k)
		}
		for k := range g {
			if _, ok := w[k]; !ok {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			if d := diff(path+"."+k, g[k], w[k]); d != "" {
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
			if d := diff(fmt.Sprintf("%s[%d]", path, i), g[i], w[i]); d != "" {
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

func TestRunTargetDemoSummaryMatchesPython(t *testing.T) {
	s := newStore(t)
	target := demoTarget(t, s, "")
	summary, err := (&Runner{Store: s}).Run(t.Context(), "", target, "rules")
	if err != nil {
		t.Fatal(err)
	}
	// overview is Go-only (no Python counterpart); TestRunTargetOverview covers it.
	for _, volatile := range []string{"target_id", "report_url", "duration_ms", "overview", "overview_truncated"} {
		delete(summary, volatile)
	}
	raw, _ := json.Marshal(summary)
	var got, want any
	_ = json.Unmarshal(raw, &got)
	expected, _ := os.ReadFile("../../testdata/golden/web_demo_summary.json")
	_ = json.Unmarshal(expected, &want)
	if d := diff("$", got, want); d != "" {
		t.Errorf("GUI summary differs from Python: %s", d)
	}
	id := target["id"].(string)
	if stored := s.LoadSummary("", id); stored == nil || stored["run_generation"] == nil || len(s.CurrentReport("", id)) == 0 {
		t.Error("the run must publish its summary and report")
	}
}

func TestRunTargetOverview(t *testing.T) {
	s := newStore(t)
	summary, err := (&Runner{Store: s}).Run(t.Context(), "", demoTarget(t, s, ""), "rules")
	if err != nil {
		t.Fatal(err)
	}
	rows, ok := summary["overview"].([]map[string]any)
	if !ok || len(rows) != summary["total"].(int) {
		t.Fatalf("overview = %#v, want one row per finding (%v)", summary["overview"], summary["total"])
	}
	if summary["overview_truncated"] != false {
		t.Error("demo overview must not be truncated")
	}
	paths := summary["decision_paths"].([]map[string]any)
	outcomes := map[string]int{}
	for i, row := range rows {
		for _, key := range []string{"finding_key", "vuln_id", "package", "decision", "decision_label",
			"exploitation", "system_exposure", "automatable", "human_impact"} {
			if strOf(row[key]) == "" {
				t.Errorf("row %d: missing %s: %#v", i, key, row)
			}
		}
		if _, ok := row["assumed"].([]string); !ok {
			t.Errorf("row %d: assumed must be a list: %#v", i, row["assumed"])
		}
		// path links the row to its detailed decision path in decision_paths.
		if p, ok := row["path"].(int); !ok || paths[p]["finding_key"] != row["finding_key"] {
			t.Errorf("row %d: path %v does not point at its decision path", i, row["path"])
		}
		outcomes[strOf(row["decision"])]++
	}
	for k, n := range summary["outcomes"].(map[string]int) {
		if outcomes[k] != n {
			t.Errorf("overview %s = %d, summary outcomes = %d", k, outcomes[k], n)
		}
	}
	// Rows follow the decision order, most urgent first.
	if rows[0]["decision"] != "immediate" {
		t.Errorf("first row decision = %v, want immediate", rows[0]["decision"])
	}
}

func TestRunTargetOverviewLimit(t *testing.T) {
	old := maxOverviewRows
	maxOverviewRows = 2
	defer func() { maxOverviewRows = old }()
	s := newStore(t)
	summary, err := (&Runner{Store: s}).Run(t.Context(), "", demoTarget(t, s, ""), "rules")
	if err != nil {
		t.Fatal(err)
	}
	if rows := summary["overview"].([]map[string]any); len(rows) != 2 || summary["overview_truncated"] != true {
		t.Errorf("overview rows = %d truncated = %v, want 2 and true", len(rows), summary["overview_truncated"])
	}
}

func TestRunTargetStaleRevisionNotSaved(t *testing.T) {
	s := newStore(t)
	target := demoTarget(t, s, wsA)
	id := target["id"].(string)
	if _, err := s.UpdateInputs(wsA, id, map[string]any{"safety_impact": "negligible"}, false); err != nil {
		t.Fatal(err)
	}
	// target still carries the old revision: the run must not publish.
	if _, err := (&Runner{Store: s}).Run(t.Context(), wsA, target, "rules"); !errors.Is(err, ErrStaleInput) {
		t.Errorf("err = %v, want ErrStaleInput", err)
	}
	if s.LoadSummary(wsA, id) != nil {
		t.Error("stale result published")
	}
}

func TestRunTargetWithoutEvidenceFails(t *testing.T) {
	s := newStore(t)
	target := mustAdd(t, s, wsA, map[string]any{"name": "empty"})
	if _, err := (&Runner{Store: s}).Run(t.Context(), wsA, target, "rules"); err == nil {
		t.Error("a target without evidence cannot run")
	}
}

func TestAggregateFleetExcludesUnassessed(t *testing.T) {
	s := newStore(t)
	demo := demoTarget(t, s, wsA)
	mustAdd(t, s, wsA, map[string]any{"name": "idle"})
	if _, err := (&Runner{Store: s}).Run(t.Context(), wsA, demo, "rules"); err != nil {
		t.Fatal(err)
	}
	fleet, err := AggregateFleet(s, wsA, nil)
	if err != nil {
		t.Fatal(err)
	}
	queue := fleet["queue"].([]map[string]any)
	if fleet["targets_total"] != 2 || fleet["targets_assessed"] != 1 || fleet["targets_unassessed"] != 1 ||
		fleet["findings_total"] != 4 || len(queue) != 4 || queue[0]["target_name"] != "Demo" ||
		queue[0]["top_priority"] != "P1" || fleet["coverage_incomplete_targets"] != 0 {
		t.Errorf("fleet = %v", fleet)
	}
}

// fakeFleetGitHub lists acme's repositories and serves an SPDX SBOM per
// repository; "broken" has no dependency graph and rateLimitAfter makes the
// n-th SBOM request hit the rate limit.
func fakeFleetGitHub(t *testing.T, names []string, rateLimitAfter int) repository.GitHub {
	t.Helper()
	var sboms int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/users/acme/repos" {
			repos := []map[string]any{}
			if r.URL.Query().Get("page") == "1" {
				for _, n := range names {
					repos = append(repos, map[string]any{"full_name": "acme/" + n, "html_url": "https://github.com/acme/" + n})
				}
			}
			_ = json.NewEncoder(w).Encode(repos)
			return
		}
		name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/repos/acme/"), "/dependency-graph/sbom")
		n := atomic.AddInt32(&sboms, 1)
		switch {
		case rateLimitAfter > 0 && int(n) >= rateLimitAfter:
			w.Header().Set("x-ratelimit-remaining", "0")
			w.WriteHeader(403)
		case name == "broken":
			http.NotFound(w, r)
		default:
			fmt.Fprintf(w, `{"sbom": {"spdxVersion": "SPDX-2.3", "name": "acme/%s", "packages": [
				{"name": "pkg0", "versionInfo": "1.0.0"}, {"name": "pkg1", "versionInfo": "1.0.0"}]}}`, name)
		}
	}))
	t.Cleanup(server.Close)
	return repository.GitHub{HTTP: server.Client(), APIRoot: server.URL, RawRoot: server.URL}
}

func names(targets []Target) string {
	var out []string
	for _, t := range targets {
		out = append(out, strOf(t["name"]))
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func TestImportFleetCreatesEvidenceAttachedTargets(t *testing.T) {
	s := &Store{Root: t.TempDir()}
	f := FleetImport{Store: s, GitHub: fakeFleetGitHub(t, []string{"app", "api", "broken"}, 0)}
	report, err := f.Import(context.Background(), "", "https://github.com/acme", 10, false, false,
		map[string]string{"system_exposure": "open"})
	if err != nil {
		t.Fatal(err)
	}
	if report["imported"] != 2 || report["failed"] != 1 || report["stopped_reason"] != "" {
		t.Errorf("report = %v", report)
	}
	targets, _ := s.Load("")
	if names(targets) != "acme/api,acme/app" {
		t.Errorf("targets = %s (a failed repository must not leave an evidence-less target)", names(targets))
	}
	for _, target := range targets {
		if target["source_kind"] != "repository" || target["source_format"] != "spdx" || target["system_exposure"] != "open" ||
			strOf(target["source_sha256"]) == "" {
			t.Errorf("target = %v", target)
		}
	}
	// Reruns are idempotent.
	again, err := f.Import(context.Background(), "", "https://github.com/acme", 10, false, false, nil)
	if err != nil || again["imported"] != 0 || again["already_imported"] != 2 {
		t.Errorf("rerun = %v, %v", again, err)
	}
	if targets, _ := s.Load(""); len(targets) != 2 {
		t.Errorf("rerun duplicated targets: %s", names(targets))
	}
}

func TestImportFleetStopsVisiblyAtLimits(t *testing.T) {
	s := &Store{Root: t.TempDir()}
	f := FleetImport{Store: s, GitHub: fakeFleetGitHub(t, []string{"one", "two", "three"}, 0), MaxTargets: 2}
	report, err := f.Import(context.Background(), "", "https://github.com/acme", 10, false, false, nil)
	if err != nil || report["imported"] != 2 || report["not_attempted"] != 1 ||
		!strings.Contains(report["stopped_reason"].(string), "target limit") {
		t.Errorf("target limit: %v, %v", report, err)
	}

	s = &Store{Root: t.TempDir()}
	f = FleetImport{Store: s, GitHub: fakeFleetGitHub(t, []string{"one", "two", "three"}, 2)}
	report, err = f.Import(context.Background(), "", "https://github.com/acme", 10, false, false, nil)
	if err != nil || report["imported"] != 1 || report["failed"] != 1 || report["not_attempted"] != 1 ||
		!strings.Contains(report["stopped_reason"].(string), "rate limit") {
		t.Errorf("rate limit: %v, %v", report, err)
	}
	if targets, _ := s.Load(""); names(targets) != "acme/one" {
		t.Errorf("rate-limited placeholder not rolled back: %s", names(targets))
	}

	_, err = f.Import(context.Background(), "", "https://github.com/acme", 10, false, false, map[string]string{"name": "evil"})
	if err == nil || !strings.Contains(err.Error(), "unsupported fleet context") {
		t.Errorf("unknown context err = %v", err)
	}
}
