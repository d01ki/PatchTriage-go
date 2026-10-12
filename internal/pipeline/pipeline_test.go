package pipeline

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/d01ki/PatchTriage-go/data"
	"github.com/d01ki/PatchTriage-go/internal/decision"
	"github.com/d01ki/PatchTriage-go/internal/ingest"
	"github.com/d01ki/PatchTriage-go/internal/model"
)

func f64(v float64) *float64 { return &v }
func sp(s string) *string    { return &s }

func triage(findings []*model.Finding) []*model.Finding {
	for _, f := range findings {
		f.Triage = decision.Triage(f)
	}
	return findings
}

// triagedFindings mirrors tests/test_pipeline.py::_triaged_findings.
func triagedFindings(t *testing.T) []*model.Finding {
	t.Helper()
	var raw []model.RawFinding
	for _, name := range []string{"trivy", "grype"} {
		content, _ := data.ReadFile("fixtures/" + name + "_sample.json")
		parsed, err := ingest.ParseScanner(content, name, nil)
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, parsed...)
	}
	findings := ingest.Dedup(raw)
	exposed := true
	for _, f := range findings {
		f.Asset.InternetExposed, f.Asset.Criticality = &exposed, "critical"
		f.Asset.SystemExposure, f.Asset.Automatable = "open", "yes"
		f.Asset.MissionImpact, f.Asset.SafetyImpact = "mef_failure", "critical"
		switch {
		case strings.Contains(f.Package.Name, "libc"):
			f.Enrichment = model.Enrichment{InCISAKEV: true, KEVRansomware: true, EPSSScore: f64(0.856), NVDCVSSScore: f64(7.8)}
		case f.Package.Name == "xz-utils":
			f.Enrichment = model.Enrichment{EPSSScore: f64(0.372), NVDCVSSScore: f64(10.0)}
		case f.Package.Name == "lodash":
			f.Enrichment = model.Enrichment{EPSSScore: f64(0.018), NVDCVSSScore: f64(7.2)}
		}
	}
	return triage(findings)
}

func find(findings []*model.Finding, match func(*model.Finding) bool) *model.Finding {
	for _, f := range findings {
		if match(f) {
			return f
		}
	}
	return nil
}

func libc(findings []*model.Finding) *model.Finding {
	return find(findings, func(f *model.Finding) bool { return strings.Contains(f.Package.Name, "libc") })
}

func TestAuditVerifiesDeterministicTriage(t *testing.T) {
	findings := triagedFindings(t)
	summary := AuditAll(findings)
	if summary.Verified != summary.Total || summary.Total != len(findings) {
		t.Errorf("summary = %+v", summary)
	}
	for _, f := range findings {
		if f.Triage.Audit["verified"] != true {
			t.Errorf("%s audit = %v", f.VulnID, f.Triage.Audit)
		}
	}
}

func hasFlag(result map[string]any, prefix string) bool {
	for _, flag := range result["flags"].([]string) {
		if strings.HasPrefix(flag, prefix) {
			return true
		}
	}
	return false
}

func TestAuditDetectsTamperedOutcome(t *testing.T) {
	findings := triagedFindings(t)
	f := findings[0]
	f.Triage.Rationale = "EPSS of 0.99 demands urgency."
	if r := AuditFinding(f); r["verified"] != false || !hasFlag(r, "fabricated_number") {
		t.Errorf("fabricated number: %v", r)
	}
	l := libc(triagedFindings(t))
	l.Triage.Priority, l.Triage.Rationale = "P4", "seems fine"
	if r := AuditFinding(l); !hasFlag(r, "ssvc_priority_mismatch") {
		t.Errorf("priority mismatch: %v", r)
	}
	g := triagedFindings(t)[0]
	g.Package.FixedVersion = ""
	g.Triage.Action, g.Triage.Rationale = "patch_immediately", "patch it"
	if r := AuditFinding(g); !hasFlag(r, "patch_without_fix") {
		t.Errorf("patch without fix: %v", r)
	}
	h := triagedFindings(t)[0]
	h.Triage.Action, h.Triage.SuggestedDeadlineDays = "monitor", 999
	if r := AuditFinding(h); !hasFlag(r, "ssvc_action_mismatch") || !hasFlag(r, "ssvc_deadline_mismatch") {
		t.Errorf("action/deadline mismatch: %v", r)
	}
	i := triagedFindings(t)[0]
	i.Triage.SSVC.Decision = "defer"
	if r := AuditFinding(i); !hasFlag(r, "ssvc_decision_mismatch") {
		t.Errorf("decision tamper: %v", r)
	}
}

func TestAuditNumericClaims(t *testing.T) {
	f := triagedFindings(t)[0]
	for _, ok := range []string{"Step 1: require TLS 1.3 at the edge.", "EPSS is 37.2% and CVSS is 10.0.",
		"Patch within 30 days.", "See https://example.test/v9.9 dated 2024-01-02."} {
		f.Triage.Rationale = ok
		if r := AuditFinding(f); hasFlag(r, "fabricated") {
			t.Errorf("%q flagged: %v", ok, r["flags"])
		}
	}
	for text, flag := range map[string]string{"EPSS is 42.4%.": "fabricated_percentage:rationale:42.4%",
		"Upgrade after 6.6 days.": "fabricated_number:rationale:6.6"} {
		f.Triage.Rationale = text
		if r := AuditFinding(f); !hasFlag(r, flag) {
			t.Errorf("%q: flags %v, want %s", text, r["flags"], flag)
		}
	}
	// "v1.5 score": Python's lookbehind rejects "1" but still audits "5".
	f.Triage.Rationale = "score v1.5"
	if r := AuditFinding(f); !hasFlag(r, "fabricated_number:rationale:5") {
		t.Errorf("lookbehind semantics: %v", r["flags"])
	}
}

func TestBuildPlanGroupsAndRanks(t *testing.T) {
	actions := BuildPlan(triagedFindings(t))
	if actions[0].Package != "libc6" || actions[0].KEVCount != 1 || actions[0].Kind != "upgrade" ||
		!strings.Contains(actions[0].Summary, "2.36-9+deb12u3") {
		t.Errorf("first action = %+v", actions[0])
	}
	raw := func(id, eco, version, fixed string) model.RawFinding {
		a := model.NewAsset("asset-1")
		a.SystemExposure, a.Automatable, a.MissionImpact, a.SafetyImpact = "open", "yes", "mef_failure", "critical"
		return model.RawFinding{VulnID: id, SourceScanner: "scanner", Asset: a, Severity: model.SeverityHigh,
			Package: model.Package{Name: "widget", Version: version, Ecosystem: eco, FixedVersion: fixed}}
	}
	plan := func(raws ...model.RawFinding) []Action {
		findings := ingest.Dedup(raws)
		for _, f := range findings {
			f.Enrichment = model.Enrichment{ExploitSourcesChecked: []string{"nvd"}, NVDCVSSScore: f64(7.5)}
		}
		return BuildPlan(triage(findings))
	}
	if a := plan(raw("CVE-2026-0010", "npm", "1.0", "9.9"), raw("CVE-2026-0011", "npm", "1.0", "10.0")); len(a) != 1 ||
		a[0].TargetVersion != "10.0" || strings.Join(a[0].TargetVersionCandidates, ",") != "9.9,10.0" ||
		a[0].ActionID != "upgrade:asset-1:npm::widget:1.0" {
		t.Errorf("highest fix: %+v", a)
	}
	if a := plan(raw("CVE-2026-0020", "debian", "1.0", "2.0~rc1"), raw("CVE-2026-0021", "deb", "1.0", "2.0")); a[0].TargetVersion != "2.0" ||
		strings.Join(a[0].TargetVersionCandidates, ",") != "2.0~rc1,2.0" {
		t.Errorf("debian tilde: %+v", a)
	}
	if a := plan(raw("CVE-2026-0030", "pypi", "1.0", "1.0"), raw("CVE-2026-0031", "pypi", "1.0", "1.0-1")); a[0].TargetVersion != "1.0-1" {
		t.Errorf("pep440 post release: %+v", a)
	}
	if a := plan(raw("CVE-2026-0022", "npm", "1.0", "2.0"), raw("CVE-2026-0023", "npm", "1.1", "2.0")); len(a) != 2 {
		t.Errorf("separate installs: %+v", a)
	}
	if a := plan(raw("CVE-2026-0024", "npm", "1.0", "")); a[0].Kind != "mitigate" ||
		a[0].Summary != "No fixed version confirmed for widget on asset-1 - investigate vendor guidance and apply mitigations" {
		t.Errorf("mitigate: %+v", a)
	}
}

func TestBuildPlanPreservesForensicObligation(t *testing.T) {
	bodFinding := func(id, automatable, technical string, kev bool) *model.Finding {
		a := model.NewAsset("asset")
		a.PubliclyExposed, a.BOD2604Applicability = "yes", "voluntary"
		f := &model.Finding{Key: id + "|pkg|asset", VulnID: id, Asset: a,
			Package: model.Package{Name: "pkg", Version: "1.2.3", FixedVersion: "1.2.4"},
			Enrichment: model.Enrichment{InCISAKEV: kev, SSVCAutomatable: sp(automatable), SSVCTechnicalImpact: sp(technical),
				RetrievalStatus: map[string]string{"kev": map[bool]string{true: "listed", false: "not_listed"}[kev], "vulnrichment": "found"}}}
		f.Triage = decision.Triage(f)
		return f
	}
	urgent := bodFinding("CVE-2024-0001", "yes", "total", true)
	other := bodFinding("CVE-2024-0002", "no", "partial", false)
	decision.ApplyPolicy([]*model.Finding{urgent, other})
	actions := BuildPlan([]*model.Finding{urgent, other})
	if len(actions) != 1 {
		t.Fatalf("actions = %d", len(actions))
	}
	a := actions[0]
	rule := a.EffectiveRule
	if a.BOD2604["outcome"] != "3DF" || a.BOD2604["forensic_triage"] != true || !contains(a.Obligations, "forensic_triage") ||
		*a.EffectiveDeadlineDays != 3 || (rule != "bod_maximum" && rule != "workflow_target_stricter") ||
		a.DeadlineDays != min(urgent.Triage.SuggestedDeadlineDays, other.Triage.SuggestedDeadlineDays) {
		t.Errorf("action = %+v", a)
	}
	raw, _ := json.Marshal(BuildPlan(triage([]*model.Finding{{Key: "k", VulnID: "CVE-1", Asset: model.NewAsset("a")}}))[0])
	if !strings.Contains(string(raw), `"bod2604":null`) || !strings.Contains(string(raw), `"effective_deadline_days":null`) {
		t.Errorf("an action without a policy keeps null policy fields: %s", raw)
	}
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func TestEvaluateTopK(t *testing.T) {
	findings := triagedFindings(t)
	row := Evaluate(findings, []int{1})[0]
	if row.KEVBaseline != 0 || row.KEVEPSS != 1 || row.KEVPatchTriage != 1 || row.EPSSEPSS != 0.856 ||
		row.EPSSPatchTriage <= row.EPSSBaseline {
		t.Errorf("row = %+v", row)
	}
	if rows := Evaluate(nil, nil); len(rows) != 0 {
		t.Errorf("empty inventory rows = %v", rows)
	}
	if rows := Evaluate(findings, nil); len(rows) != 3 || rows[0].K != 1 || rows[1].K != 2 || rows[2].K != 4 {
		t.Errorf("default budgets = %+v", rows)
	}
	outcome := EvaluationOutcome(row, len(findings))
	if outcome["review_reduction_pct"] != 75.0 || outcome["kev_coverage_pct"] != 100.0 ||
		outcome["kev_gain_points"] != 100.0 || outcome["additional_kev_vs_cvss"] != 1 || outcome["kev_lift_vs_cvss"] != nil {
		t.Errorf("outcome = %v", outcome)
	}
}

func TestPresentation(t *testing.T) {
	l := libc(triagedFindings(t))
	if PriorityDefinition("P1")["label"] != "Immediate" || PriorityDefinition("bogus")["code"] != "P4" ||
		!strings.HasPrefix(PriorityBasis(l), "The SSVC Deployer path") {
		t.Error("priority definition/basis")
	}
	checks := map[string]map[string]string{}
	for _, c := range PriorityEvidence(l) {
		checks[c["label"]] = c
	}
	if checks["Exploitation"]["status"] != "confirmed" || !strings.Contains(checks["Exploitation"]["value"], "Active") ||
		checks["Fix readiness"]["status"] != "confirmed" || checks["Technical Impact"]["status"] != "unknown" {
		t.Errorf("checks = %v", checks)
	}
}

func qualityFinding(key string, e model.Enrichment) *model.Finding {
	a := model.NewAsset("asset")
	a.SystemExposure, a.MissionImpact, a.SafetyImpact = "open", "mef_failure", "marginal"
	f := &model.Finding{Key: key, VulnID: "CVE-2024-3400", Package: model.Package{Name: "pkg"}, Asset: a, Enrichment: e}
	f.Triage = decision.Triage(f)
	return f
}

func TestDecisionQuality(t *testing.T) {
	q := DecisionQuality([]*model.Finding{qualityFinding("k", model.Enrichment{})})
	if q["findings"] != 1 || q["points_total"] != 2 || q["authoritative"] != 0 || q["assumed"] != 2 ||
		q["needs_confirmation"] != 1 || q["sources"].(Counts).Get("SSVC conservative default") == 0 {
		t.Errorf("default = %v", q)
	}
	published := DecisionQuality([]*model.Finding{qualityFinding("k", model.Enrichment{SSVCExploitation: sp("poc"), SSVCAutomatable: sp("no")})})
	if published["authoritative"] != 2 || published["authoritative_pct"] != 100.0 || published["de_escalated"] != 1 ||
		published["sources"].(Counts).Get("CISA Vulnrichment") != 2 {
		t.Errorf("published = %v", published)
	}
	if q := DecisionQuality([]*model.Finding{qualityFinding("k", model.Enrichment{SSVCAutomatable: sp("yes")})}); q["de_escalated"] != 0 {
		t.Errorf("a published Yes is no de-escalation: %v", q)
	}
	if q := DecisionQuality([]*model.Finding{qualityFinding("k", model.Enrichment{InCISAKEV: true})}); q["sources"].(Counts).Get("CISA KEV") != 1 {
		t.Errorf("KEV: %v", q)
	}
	untriaged := &model.Finding{Key: "u", VulnID: "CVE-2024-0001", Asset: model.NewAsset("asset")}
	if q := DecisionQuality([]*model.Finding{qualityFinding("k", model.Enrichment{}), untriaged}); q["findings"] != 1 || q["points_total"] != 2 {
		t.Errorf("untriaged: %v", q)
	}
	if q := DecisionQuality(nil); q["points_total"] != 0 || q["authoritative_pct"] != 0.0 {
		t.Errorf("empty: %v", q)
	}
	raw, _ := json.Marshal(DecisionQuality([]*model.Finding{qualityFinding("a", model.Enrichment{}),
		qualityFinding("b", model.Enrichment{SSVCExploitation: sp("poc"), SSVCAutomatable: sp("no")}),
		qualityFinding("c", model.Enrichment{SSVCExploitation: sp("poc"), SSVCAutomatable: sp("no")})})["sources"])
	if string(raw) != `{"CISA Vulnrichment":4,"unconfirmed default":1,"SSVC conservative default":1}` {
		t.Errorf("sources keep count order then first-seen order: %s", raw)
	}
}

func TestAssetFromTarget(t *testing.T) {
	var target map[string]any
	_ = json.Unmarshal([]byte(`{"name": "checkout", "source_format": "spdx", "criticality": "high", "internet_exposed": true,
		"system_exposure": "open", "mission_impact": "mef_failure", "safety_impact": "critical", "automatable": "yes",
		"publicly_exposed": "yes", "bod2604_applicability": "voluntary", "context_sources": ["reviewer"]}`), &target)
	a := AssetFromTarget(target)
	if a.Identifier != "checkout" || a.Kind != "sbom" || a.Criticality != "high" || a.InternetExposed == nil || !*a.InternetExposed ||
		a.Reachable != nil || a.SystemExposure != "open" || a.MissionImpact != "mef_failure" || a.SafetyImpact != "critical" ||
		a.Automatable != "unknown" || a.PubliclyExposed != "yes" || a.BOD2604Applicability != "voluntary" ||
		strings.Join(a.ContextSources, ",") != "reviewer" {
		t.Errorf("asset = %+v", a)
	}
	if AssetFromTarget(map[string]any{"name": "r", "source_kind": "repository"}).Kind != "repository" ||
		AssetFromTarget(map[string]any{"name": "h"}).Kind != "host" {
		t.Error("asset kind mapping")
	}
}
