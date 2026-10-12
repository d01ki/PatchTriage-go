// Package validation is the offline, reviewer-runnable conformance and
// reproducibility proof behind `patchtriage verify`.
package validation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/d01ki/PatchTriage-go/data"
	"github.com/d01ki/PatchTriage-go/internal/decision"
	"github.com/d01ki/PatchTriage-go/internal/enrich"
	"github.com/d01ki/PatchTriage-go/internal/ingest"
	"github.com/d01ki/PatchTriage-go/internal/model"
	"github.com/d01ki/PatchTriage-go/internal/pipeline"
)

type spec struct {
	Schema   string            `json:"schema"`
	Sources  map[string]string `json:"sources"`
	Deployer struct {
		HumanImpactOrder []string          `json:"human_impact_order"`
		OutcomeCodes     map[string]string `json:"outcome_codes"`
		Rows             []struct {
			Exploitation   string `json:"exploitation"`
			SystemExposure string `json:"system_exposure"`
			Automatable    string `json:"automatable"`
			Expected       string `json:"expected"`
		} `json:"rows"`
	} `json:"deployer"`
	HumanImpact struct {
		MissionOrder []string `json:"mission_order"`
		Rows         []struct {
			SafetyImpact string   `json:"safety_impact"`
			Expected     []string `json:"expected"`
		} `json:"rows"`
	} `json:"human_impact"`
	TargetSensitivity []struct {
		Name             string            `json:"name"`
		Context          map[string]string `json:"context"`
		ExpectedDecision string            `json:"expected_decision"`
	} `json:"target_sensitivity"`
	UnknownContext struct {
		Expected          map[string]string `json:"expected"`
		NeedsConfirmation []string          `json:"needs_confirmation"`
	} `json:"unknown_context"`
	DemoExpected map[string]string `json:"demo_expected"`
}

// canonical is JSON with sorted keys, compact separators and raw non-ASCII,
// like Python's json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False).
func canonical(value any) []byte {
	raw, _ := json.Marshal(value)
	var generic any
	_ = json.Unmarshal(raw, &generic)
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(generic)
	return bytes.TrimRight(b.Bytes(), "\n")
}

func sha(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func check(name string, cases int, failures []any, observations any) map[string]any {
	if failures == nil {
		failures = []any{}
	}
	result := map[string]any{"name": name, "passed": len(failures) == 0, "cases": cases,
		"passed_cases": max(0, cases-len(failures)), "failures": failures}
	if observations != nil {
		result["observations"] = observations
	}
	return result
}

func deployerCheck(s spec) (map[string]any, any) {
	var failures []any
	var observations []map[string]string
	for _, row := range s.Deployer.Rows {
		for i, human := range s.Deployer.HumanImpactOrder {
			expected := s.Deployer.OutcomeCodes[string(row.Expected[i])]
			actual := string(decision.DeployerDecision(decision.Exploitation(row.Exploitation),
				decision.SystemExposure(row.SystemExposure), decision.Automatable(row.Automatable), decision.HumanImpact(human)))
			c := map[string]string{"exploitation": row.Exploitation, "system_exposure": row.SystemExposure,
				"automatable": row.Automatable, "human_impact": human, "expected": expected, "actual": actual}
			observations = append(observations, c)
			if actual != expected {
				failures = append(failures, c)
			}
		}
	}
	return check("official_ssvc_deployer_table", len(observations), failures,
		map[string]string{"source": s.Sources["deployer"]}), observations
}

func humanImpactCheck(s spec) (map[string]any, any) {
	var failures []any
	var observations []map[string]string
	for _, row := range s.HumanImpact.Rows {
		for i, mission := range s.HumanImpact.MissionOrder {
			actual := string(decision.DeriveHumanImpact(decision.MissionImpact(mission), decision.SafetyImpact(row.SafetyImpact)))
			c := map[string]string{"mission_impact": mission, "safety_impact": row.SafetyImpact,
				"expected": row.Expected[i], "actual": actual}
			observations = append(observations, c)
			if actual != row.Expected[i] {
				failures = append(failures, c)
			}
		}
	}
	return check("official_ssvc_human_impact_table", len(observations), failures,
		map[string]string{"source": s.Sources["human_impact"]}), observations
}

// snapshot is the frozen EPSS/KEV/NVD evidence (no Vulnrichment, like Python's verify).
func snapshot() (enrich.Snapshot, error) {
	s, err := enrich.DemoSnapshot()
	s.Vulnrichment = nil
	return s, err
}

func targetSensitivityCheck(s spec) (map[string]any, any, []*model.Finding, error) {
	frozen, err := snapshot()
	if err != nil {
		return nil, nil, nil, err
	}
	fixture, err := data.ReadFile("fixtures/trivy_sample.json")
	if err != nil {
		return nil, nil, nil, err
	}
	var failures []any
	var observations []map[string]any
	var findings []*model.Finding
	expectedOutcomes, actualOutcomes := map[string]bool{}, map[string]bool{}
	for _, scenario := range s.TargetSensitivity {
		target := map[string]any{"name": scenario.Name, "source_format": "trivy", "context_sources": []any{"reviewer-fixture"}}
		for k, v := range scenario.Context {
			target[k] = v
		}
		asset := pipeline.AssetFromTarget(target)
		raw, err := ingest.ParseScanner(fixture, "trivy", &asset)
		if err != nil {
			return nil, nil, nil, err
		}
		parsed := ingest.Dedup(raw)
		enrich.EnrichFromSnapshot(parsed, frozen)
		var finding *model.Finding
		for _, f := range parsed {
			if f.VulnID == "CVE-2023-4911" {
				finding = f
			}
		}
		if finding == nil {
			return nil, nil, nil, errors.New("fixture lacks CVE-2023-4911")
		}
		finding.Triage = decision.Triage(finding)
		ssvc := finding.Triage.SSVC
		mapped := map[string]string{"system_exposure": finding.Asset.SystemExposure,
			"mission_impact": finding.Asset.MissionImpact, "safety_impact": finding.Asset.SafetyImpact}
		c := map[string]any{
			"name": scenario.Name, "same_vulnerability": finding.VulnID, "same_package": finding.Package.Name,
			"same_threat_evidence":   "frozen CISA KEV / Active",
			"pipeline":               "Trivy -> target mapping -> snapshot enrichment -> SSVC",
			"target_context_entered": scenario.Context, "target_context_consumed": mapped,
			"vulnerability_automatable": map[string]string{"value": ssvc.Automatable.Value, "source": ssvc.Automatable.Source},
			"expected_decision":         scenario.ExpectedDecision, "actual_decision": ssvc.Decision,
			"decision_path": ssvc.DecisionPath,
		}
		observations = append(observations, c)
		findings = append(findings, finding)
		expectedOutcomes[scenario.ExpectedDecision], actualOutcomes[ssvc.Decision] = true, true
		if fmt.Sprint(mapped) != fmt.Sprint(scenario.Context) || ssvc.Decision != scenario.ExpectedDecision {
			failures = append(failures, c)
		}
	}
	keys := func(m map[string]bool) []string {
		var out []string
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	if strings.Join(keys(expectedOutcomes), ",") != strings.Join(keys(actualOutcomes), ",") {
		failures = append(failures, map[string]any{"reason": "target context did not produce the expected outcome spread",
			"expected": keys(expectedOutcomes), "actual": keys(actualOutcomes)})
	}
	return check("target_context_mapping_sensitivity", len(observations), failures, observations), observations, findings, nil
}

func unknownContextCheck(s spec) (map[string]any, any) {
	f := &model.Finding{Key: "unknown-context", VulnID: "CVE-2099-0002",
		Package: model.Package{Name: "unknown-context-component", Version: "1.0.0"}, Asset: model.NewAsset("unknown-target"),
		Enrichment: model.Enrichment{Sources: []string{"frozen-validation-snapshot"}}}
	a := decision.Assess(f)
	actual := map[string]string{"system_exposure": a.SystemExposure.Value, "automatable": a.Automatable.Value,
		"mission_impact": a.MissionImpact.Value, "safety_impact": a.SafetyImpact.Value, "decision": a.Decision}
	expectedConfirmation := append([]string{}, s.UnknownContext.NeedsConfirmation...)
	actualConfirmation := append([]string{}, a.NeedsConfirmation...)
	sort.Strings(expectedConfirmation)
	sort.Strings(actualConfirmation)
	var failures []any
	if fmt.Sprint(actual) != fmt.Sprint(s.UnknownContext.Expected) ||
		strings.Join(actualConfirmation, ",") != strings.Join(expectedConfirmation, ",") {
		failures = append(failures, map[string]any{"expected": s.UnknownContext.Expected, "actual": actual,
			"expected_confirmation": expectedConfirmation, "actual_confirmation": actualConfirmation})
	}
	observation := map[string]any{"expected": s.UnknownContext.Expected, "actual": actual, "needs_confirmation": actualConfirmation}
	return check("unknown_context_is_explicit", 1, failures, observation), observation
}

func projection(f *model.Finding) map[string]any {
	a := decision.Assess(f)
	return map[string]any{
		"model": a.Model, "decision": a.Decision, "decision_path": a.DecisionPath,
		"deadline_days": a.SuggestedDeadlineDays, "recommended_action": a.RecommendedAction,
		"confidence": a.Confidence, "needs_confirmation": a.NeedsConfirmation,
		"points": map[string]model.DecisionPoint{"exploitation": a.Exploitation, "system_exposure": a.SystemExposure,
			"automatable": a.Automatable, "mission_impact": a.MissionImpact, "safety_impact": a.SafetyImpact,
			"human_impact": a.HumanImpact},
	}
}

func repeatabilityCheck(findings []*model.Finding, repeats int) (map[string]any, map[string][]string) {
	observations := map[string]any{}
	hashes := map[string][]string{}
	var failures []any
	for _, f := range findings {
		seen := map[string]bool{}
		for range repeats {
			seen[sha(canonical(projection(f)))] = true
		}
		var unique []string
		for h := range seen {
			unique = append(unique, h)
		}
		sort.Strings(unique)
		observations[f.Asset.Identifier] = map[string]any{"runs": repeats, "unique_decision_hashes": unique}
		hashes[f.Asset.Identifier] = unique
		if len(unique) != 1 {
			failures = append(failures, map[string]any{"target": f.Asset.Identifier, "unique_decision_hashes": unique})
		}
	}
	return check("repeatability", len(findings)*repeats, failures, observations), hashes
}

func demoRun() (map[string]string, map[string]any, error) {
	var raw []model.RawFinding
	for _, name := range []string{"trivy", "grype"} {
		content, err := data.ReadFile("fixtures/" + name + "_sample.json")
		if err != nil {
			return nil, nil, err
		}
		parsed, err := ingest.ParseScanner(content, name, nil)
		if err != nil {
			return nil, nil, err
		}
		raw = append(raw, parsed...)
	}
	findings := ingest.Dedup(raw)
	inventoryRaw, err := data.ReadFile("demo_assets.yaml")
	if err != nil {
		return nil, nil, err
	}
	path := filepath.Join(os.TempDir(), fmt.Sprintf("patchtriage-verify-%d.yaml", time.Now().UnixNano()))
	if err := os.WriteFile(path, inventoryRaw, 0o600); err != nil {
		return nil, nil, err
	}
	defer os.Remove(path)
	inventory, err := ingest.LoadInventory(path)
	if err != nil {
		return nil, nil, err
	}
	if _, err := ingest.ApplyContext(findings, inventory); err != nil {
		return nil, nil, err
	}
	frozen, err := snapshot()
	if err != nil {
		return nil, nil, err
	}
	enrich.EnrichFromSnapshot(findings, frozen)
	for _, f := range findings {
		f.Triage = decision.Triage(f)
	}
	audit := pipeline.AuditAll(findings)
	sort.SliceStable(findings, func(i, j int) bool { return findings[i].VulnID < findings[j].VulnID })
	outcomes := map[string]string{}
	projected := map[string]any{}
	for _, f := range findings {
		outcomes[f.VulnID] = f.Triage.SSVC.Decision
		projected[f.VulnID] = map[string]any{"package": f.Package.Name, "asset_context": map[string]string{
			"system_exposure": f.Asset.SystemExposure, "mission_impact": f.Asset.MissionImpact,
			"safety_impact": f.Asset.SafetyImpact}, "ssvc": projection(f)}
	}
	return outcomes, map[string]any{"projection_hash": sha(canonical(projected)), "audit_verified": audit.Verified,
		"audit_total": audit.Total, "audit_flagged": len(audit.Flagged)}, nil
}

func demoCheck(s spec) (map[string]any, any, error) {
	first, runOne, err := demoRun()
	if err != nil {
		return nil, nil, err
	}
	second, runTwo, err := demoRun()
	if err != nil {
		return nil, nil, err
	}
	var failures []any
	if fmt.Sprint(first) != fmt.Sprint(s.DemoExpected) {
		failures = append(failures, map[string]any{"reason": "unexpected outcomes", "expected": s.DemoExpected, "actual": first})
	}
	if fmt.Sprint(first) != fmt.Sprint(second) || runOne["projection_hash"] != runTwo["projection_hash"] {
		failures = append(failures, map[string]any{"reason": "two frozen end-to-end runs differed",
			"first": runOne["projection_hash"], "second": runTwo["projection_hash"]})
	}
	if runOne["audit_verified"] != runOne["audit_total"] || runOne["audit_flagged"] != 0 {
		failures = append(failures, map[string]any{"reason": "end-to-end audit failed", "audit": runOne})
	}
	observation := map[string]any{"expected_outcomes": s.DemoExpected, "actual_outcomes": first,
		"first_projection_hash": runOne["projection_hash"], "second_projection_hash": runTwo["projection_hash"],
		"audit": map[string]any{"verified": runOne["audit_verified"], "total": runOne["audit_total"]}}
	return check("frozen_end_to_end_pipeline", 3, failures, observation), observation, nil
}

func tamperCheck(f *model.Finding) (map[string]any, any) {
	tampered := *f
	tampered.Triage = decision.Triage(&tampered)
	tampered.Triage.Priority, tampered.Triage.Action, tampered.Triage.SuggestedDeadlineDays = "P4", "monitor", 999
	tampered.Triage.SSVC.DecisionPath = "tampered"
	audit := pipeline.AuditFinding(&tampered)
	flags := audit["flags"].([]string)
	detected := map[string]bool{}
	all := audit["verified"] == false
	for _, prefix := range []string{"ssvc_priority_mismatch", "ssvc_action_mismatch", "ssvc_deadline_mismatch", "ssvc_path_mismatch"} {
		for _, flag := range flags {
			detected[prefix] = detected[prefix] || strings.HasPrefix(flag, prefix)
		}
		all = all && detected[prefix]
	}
	var failures []any
	if !all {
		failures = append(failures, map[string]any{"expected_detections": []string{"ssvc_priority_mismatch",
			"ssvc_action_mismatch", "ssvc_deadline_mismatch", "ssvc_path_mismatch"}, "actual_flags": flags})
	}
	observation := map[string]any{"detected": detected, "audit_flags": flags}
	return check("decision_tamper_detection", 4, failures, observation), observation
}

// manifest fingerprints the frozen inputs and the engine's decision tables
// (a compiled Go binary carries no source files to hash).
func manifest() (map[string]string, error) {
	out := map[string]string{}
	for _, name := range []string{"ssvc_validation.json", "demo_assets.yaml", "demo_epss.json", "demo_kev.json",
		"demo_nvd.json", "fixtures/trivy_sample.json", "fixtures/grype_sample.json"} {
		raw, err := data.ReadFile(name)
		if err != nil {
			return nil, err
		}
		out["data/"+name] = sha(raw)
	}
	tables := map[string]string{}
	for _, e := range decision.Exploitations {
		for _, x := range decision.SystemExposures {
			for _, a := range decision.Automatables {
				for _, h := range decision.HumanImpacts {
					tables[fmt.Sprintf("deployer|%s|%s|%s|%s", e, x, a, h)] = string(decision.DeployerDecision(e, x, a, h))
				}
			}
		}
	}
	for _, m := range decision.MissionImpacts {
		for _, s := range decision.SafetyImpacts {
			tables[fmt.Sprintf("human_impact|%s|%s", m, s)] = string(decision.DeriveHumanImpact(m, s))
		}
	}
	out["engine:decision_tables"] = sha(canonical(tables))
	return out, nil
}

// Run executes every offline verification layer and returns the report.
func Run(repeats int) (map[string]any, error) {
	if repeats < 2 {
		return nil, errors.New("repeats must be at least 2")
	}
	raw, err := data.ReadFile("ssvc_validation.json")
	if err != nil {
		return nil, err
	}
	var s spec
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	var checks []map[string]any
	material := map[string]any{}
	add := func(c map[string]any, m any) {
		checks = append(checks, c)
		material[c["name"].(string)] = m
	}
	add(deployerCheck(s))
	add(humanImpactCheck(s))
	targetCheck, targetResults, targetFindings, err := targetSensitivityCheck(s)
	if err != nil {
		return nil, err
	}
	add(targetCheck, targetResults)
	add(unknownContextCheck(s))
	add(repeatabilityCheck(targetFindings, repeats))
	demo, demoResult, err := demoCheck(s)
	if err != nil {
		return nil, err
	}
	add(demo, demoResult)
	add(tamperCheck(targetFindings[0]))
	inputs, err := manifest()
	if err != nil {
		return nil, err
	}
	status := "pass"
	for _, c := range checks {
		if c["passed"] != true {
			status = "fail"
		}
	}
	return map[string]any{
		"schema": s.Schema, "generated_at": time.Now().UTC().Format(time.RFC3339Nano), "status": status,
		"offline": true, "repeats": repeats,
		"environment": map[string]string{"go": runtime.Version(), "implementation": runtime.Compiler,
			"platform": runtime.GOOS + "/" + runtime.GOARCH},
		"official_sources": s.Sources, "input_manifest_sha256": inputs,
		"input_fingerprint": sha(canonical(inputs)), "decision_fingerprint": sha(canonical(material)),
		"checks": checks,
		"claim_scope": "Conformance to the bundled official SSVC expectations, faithful GUI target-context mapping, " +
			"deterministic repeatability for frozen inputs, frozen end-to-end behavior, and detection of altered decisions.",
		"claim_limit": "This does not by itself prove real-world remediation effectiveness; that requires an " +
			"independently labeled prospective evaluation.",
	}, nil
}

// WriteReport runs the verification and writes the JSON report to path.
func WriteReport(path string, repeats int) (map[string]any, error) {
	report, err := Run(repeats)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		return nil, err
	}
	return report, os.WriteFile(path, b.Bytes(), 0o644)
}
