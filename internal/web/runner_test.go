package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
	"testing"
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
	summary, err := (&Runner{Store: s}).Run(t.Context(), "", target)
	if err != nil {
		t.Fatal(err)
	}
	for _, volatile := range []string{"target_id", "report_url", "duration_ms"} {
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

func TestRunTargetStaleRevisionNotSaved(t *testing.T) {
	s := newStore(t)
	target := demoTarget(t, s, wsA)
	id := target["id"].(string)
	if _, err := s.UpdateInputs(wsA, id, map[string]any{"safety_impact": "negligible"}, false); err != nil {
		t.Fatal(err)
	}
	// target still carries the old revision: the run must not publish.
	if _, err := (&Runner{Store: s}).Run(t.Context(), wsA, target); !errors.Is(err, ErrStaleInput) {
		t.Errorf("err = %v, want ErrStaleInput", err)
	}
	if s.LoadSummary(wsA, id) != nil {
		t.Error("stale result published")
	}
}

func TestRunTargetWithoutEvidenceFails(t *testing.T) {
	s := newStore(t)
	target := mustAdd(t, s, wsA, map[string]any{"name": "empty"})
	if _, err := (&Runner{Store: s}).Run(t.Context(), wsA, target); err == nil {
		t.Error("a target without evidence cannot run")
	}
}

func TestAggregateFleetExcludesUnassessed(t *testing.T) {
	s := newStore(t)
	demo := demoTarget(t, s, wsA)
	mustAdd(t, s, wsA, map[string]any{"name": "idle"})
	if _, err := (&Runner{Store: s}).Run(t.Context(), wsA, demo); err != nil {
		t.Fatal(err)
	}
	fleet, err := AggregateFleet(s, wsA)
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
