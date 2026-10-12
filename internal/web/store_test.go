package web

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const wsA = "0123456789abcdef0123456789abcdef"
const wsB = "fedcba9876543210fedcba9876543210"

func newStore(t *testing.T) *Store { return &Store{Root: t.TempDir()} }

func mustAdd(t *testing.T, s *Store, ws string, fields map[string]any) Target {
	t.Helper()
	target, err := s.Add(ws, fields, 0)
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func TestStoreAddValidates(t *testing.T) {
	s := newStore(t)
	target := mustAdd(t, s, wsA, map[string]any{"name": " checkout ", "url": "https://example.test/x",
		"criticality": "HIGH", "internet_exposed": true, "system_exposure": "Open", "automatable": true,
		"context_sources": "otel"})
	if target["name"] != "checkout" || target["criticality"] != "high" || target["system_exposure"] != "open" ||
		target["automatable"] != "yes" || target["internet_exposed"] != true || target["reachable"] != nil ||
		len(target["id"].(string)) != 12 || intOf(target["input_revision"]) != 0 {
		t.Errorf("target = %v", target)
	}
	for _, bad := range []map[string]any{
		{"name": ""}, {"name": strings.Repeat("x", 121)}, {"name": "x", "url": "ftp://example.test"},
		{"name": "x", "url": "https://user:pass@example.test"}, {"name": "x", "criticality": "severe"},
		{"name": "x", "mission_impact": "huge"}, {"name": "x", "internet_exposed": "yes"},
		{"name": "x", "bod2604_applicability": "maybe"},
	} {
		if _, err := s.Add(wsA, bad, 0); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestStoreSessionIsolation(t *testing.T) {
	s := newStore(t)
	target := mustAdd(t, s, wsA, map[string]any{"name": "a"})
	if _, err := s.Get(wsB, target["id"].(string)); !errors.Is(err, ErrNoTarget) {
		t.Errorf("another workspace must not see the target: %v", err)
	}
	if list, _ := s.Load(wsB); len(list) != 0 {
		t.Errorf("workspace B lists %v", list)
	}
	if _, err := s.Load("../../etc"); err == nil {
		t.Error("an invalid workspace id must be rejected")
	}
	if _, err := s.Get(wsA, "../x"); err == nil || errors.Is(err, ErrNoTarget) {
		t.Errorf("an invalid target id must be a validation error: %v", err)
	}
}

func TestStoreRejectsLimitsAndQuota(t *testing.T) {
	s := newStore(t)
	mustAdd(t, s, wsA, map[string]any{"name": "a"})
	if _, err := s.Add(wsA, map[string]any{"name": "b"}, 1); !errors.Is(err, ErrTargetLimit) {
		t.Errorf("target limit: %v", err)
	}
	target := mustAdd(t, s, wsB, map[string]any{"name": "c"})
	id := target["id"].(string)
	if err := s.SaveSource(wsB, id, strings.Repeat("x", 100), Source{Format: "trivy"}, 50); !errors.Is(err, ErrSourceQuota) {
		t.Errorf("quota: %v", err)
	}
	if err := s.SaveSource(wsB, id, `{"a": 1}`, Source{Format: "trivy"}, 50); err != nil {
		t.Fatal(err)
	}
	// Replacing the source does not count the old bytes twice.
	if err := s.SaveSource(wsB, id, `{"b": 22}`, Source{Format: "trivy"}, 12); err != nil {
		t.Errorf("replacement within quota: %v", err)
	}
}

func TestStoreInvalidatesOnChange(t *testing.T) {
	s := newStore(t)
	target := mustAdd(t, s, wsA, map[string]any{"name": "a"})
	id := target["id"].(string)
	if _, err := s.UpdateInputs(wsA, id, map[string]any{"ssvc_overrides": map[string]any{"k": map[string]any{"automatable": "no"}}}, false); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveSource(wsA, id, `{"Results": []}`, Source{Format: "trivy", Filename: "t.json", Kind: "upload",
		Provenance: map[string]any{"provider": "upload"}}, 0); err != nil {
		t.Fatal(err)
	}
	current, _ := s.Get(wsA, id)
	if len(current["ssvc_overrides"].(map[string]any)) != 0 || intOf(current["input_revision"]) != 2 ||
		current["source_name"] != "t.json" || current["source_size"] != float64(15) {
		t.Errorf("after source: %v", current)
	}
	revision, sha := intOf(current["input_revision"]), current["source_sha256"].(string)
	if err := s.SaveRunArtifacts(wsA, id, map[string]any{"total": 0}, "<html>r</html>", revision, sha); err != nil {
		t.Fatal(err)
	}
	if s.LoadSummary(wsA, id) == nil || string(s.CurrentReport(wsA, id)) != "<html>r</html>" {
		t.Fatal("published run not readable")
	}
	updated, err := s.UpdateInputs(wsA, id, map[string]any{"system_exposure": "small"}, false)
	if err != nil || intOf(updated["input_revision"]) != 3 || updated["system_exposure"] != "small" {
		t.Fatalf("update: %v %v", updated, err)
	}
	if s.LoadSummary(wsA, id) != nil || s.CurrentReport(wsA, id) != nil {
		t.Error("changed context must invalidate the summary and report")
	}
	if err := s.SaveRunArtifacts(wsA, id, map[string]any{}, "x", revision, sha); !errors.Is(err, ErrStaleInput) {
		t.Errorf("a run for an old revision must be discarded: %v", err)
	}
	if s.LoadSummary(wsA, id) != nil {
		t.Error("a stale run must not publish a summary")
	}
	if ok, err := s.Delete(wsA, id); !ok || err != nil {
		t.Fatalf("delete: %v %v", ok, err)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(s.Root, "sessions", wsA, "targets", id+"_*")); len(leftovers) != 0 {
		t.Errorf("deleted target left files: %v", leftovers)
	}
}

func TestStoreCleanupExpiredWorkspaces(t *testing.T) {
	s := newStore(t)
	mustAdd(t, s, wsA, map[string]any{"name": "old"})
	mustAdd(t, s, wsB, map[string]any{"name": "new"})
	old := time.Now().Add(-7 * time.Hour)
	_ = os.Chtimes(filepath.Join(s.Root, "sessions", wsA), old, old)
	if removed := s.Cleanup(6*time.Hour, nil); removed != 1 {
		t.Errorf("removed %d workspaces, want 1", removed)
	}
	if list, _ := s.Load(wsB); len(list) != 1 {
		t.Error("active workspace removed")
	}
}
