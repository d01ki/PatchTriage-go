package validation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyAllChecksPass(t *testing.T) {
	report, err := Run(3)
	if err != nil {
		t.Fatal(err)
	}
	if report["status"] != "pass" || report["offline"] != true || report["schema"] != "patchtriage-validation:1.0.0" {
		t.Errorf("report = %v", report)
	}
	want := map[string]int{
		"official_ssvc_deployer_table": 72, "official_ssvc_human_impact_table": 16,
		"target_context_mapping_sensitivity": 3, "unknown_context_is_explicit": 1,
		"repeatability": 9, "frozen_end_to_end_pipeline": 3, "decision_tamper_detection": 4,
	}
	checks := report["checks"].([]map[string]any)
	if len(checks) != len(want) {
		t.Fatalf("checks = %d, want %d", len(checks), len(want))
	}
	for _, c := range checks {
		name := c["name"].(string)
		if c["passed"] != true || c["cases"] != want[name] || c["passed_cases"] != want[name] {
			t.Errorf("%s: passed=%v cases=%v (want %d), failures %v", name, c["passed"], c["cases"], want[name], c["failures"])
		}
	}
	if _, err := Run(1); err == nil {
		t.Error("repeats below 2 must be rejected")
	}
}

func TestVerifyFingerprintStable(t *testing.T) {
	first, err := Run(2)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := Run(2)
	if first["input_fingerprint"] != second["input_fingerprint"] || first["decision_fingerprint"] != second["decision_fingerprint"] {
		t.Errorf("fingerprints differ between identical runs")
	}
	if len(first["input_fingerprint"].(string)) != 64 || len(first["decision_fingerprint"].(string)) != 64 {
		t.Error("fingerprints must be SHA-256 hex digests")
	}
}

func TestTamperCheckDetects(t *testing.T) {
	report, _ := Run(2)
	for _, c := range report["checks"].([]map[string]any) {
		if c["name"] != "decision_tamper_detection" {
			continue
		}
		detected := c["observations"].(map[string]any)["detected"].(map[string]bool)
		for _, prefix := range []string{"ssvc_priority_mismatch", "ssvc_action_mismatch", "ssvc_deadline_mismatch", "ssvc_path_mismatch"} {
			if !detected[prefix] {
				t.Errorf("tamper %s not detected", prefix)
			}
		}
	}
}

func TestWriteReport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out", "verification_report.json")
	if _, err := WriteReport(path, 2); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	var decoded map[string]any
	if err != nil || json.Unmarshal(raw, &decoded) != nil || decoded["status"] != "pass" {
		t.Errorf("written report: %v %s", err, raw[:min(len(raw), 200)])
	}
}
