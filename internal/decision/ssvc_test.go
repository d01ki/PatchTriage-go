package decision

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/d01ki/PatchTriage-go/data"
	"github.com/d01ki/PatchTriage-go/internal/model"
)

func strp(s string) *string   { return &s }
func f64p(v float64) *float64 { return &v }
func boolp(b bool) *bool      { return &b }

func newFinding() *model.Finding {
	return &model.Finding{Key: "k", VulnID: "CVE-2024-3400",
		Package: model.Package{Name: "pkg", FixedVersion: "2.0"}, Asset: model.NewAsset("checkout")}
}

// explicit sets the target context used by most Python tests.
func explicit(f *model.Finding, exposure, automatable, mission, safety string) *model.Finding {
	f.Asset.SystemExposure, f.Asset.Automatable = exposure, automatable
	f.Asset.MissionImpact, f.Asset.SafetyImpact = mission, safety
	return f
}

func contextual() *model.Finding {
	return explicit(newFinding(), "open", "yes", "mef_failure", "marginal")
}

func TestDeployerTableMatchesOfficial(t *testing.T) {
	raw, err := data.ReadFile("ssvc_validation.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
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
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	paths, outcomes := 0, map[Decision]bool{}
	for _, r := range spec.Deployer.Rows {
		for i, human := range spec.Deployer.HumanImpactOrder {
			want := Decision(spec.Deployer.OutcomeCodes[string(r.Expected[i])])
			got := DeployerDecision(Exploitation(r.Exploitation), SystemExposure(r.SystemExposure),
				Automatable(r.Automatable), HumanImpact(human))
			if got != want {
				t.Errorf("%s/%s/%s/%s = %s, official %s", r.Exploitation, r.SystemExposure, r.Automatable, human, got, want)
			}
			paths++
			outcomes[got] = true
		}
	}
	if paths != 72 || len(outcomes) != 4 {
		t.Errorf("checked %d paths and %d outcomes, want 72 and 4", paths, len(outcomes))
	}
	combinations := 0
	for _, row := range spec.HumanImpact.Rows {
		for i, mission := range spec.HumanImpact.MissionOrder {
			if got := DeriveHumanImpact(MissionImpact(mission), SafetyImpact(row.SafetyImpact)); string(got) != row.Expected[i] {
				t.Errorf("Human Impact %s x %s = %s, official %s", mission, row.SafetyImpact, got, row.Expected[i])
			}
			combinations++
		}
	}
	if combinations != 16 {
		t.Errorf("checked %d Human Impact combinations, want 16", combinations)
	}
}

func TestKeyOfficialDeployerPaths(t *testing.T) {
	cases := []struct {
		e    Exploitation
		x    SystemExposure
		a    Automatable
		h    HumanImpact
		want Decision
	}{
		{ExploitationActive, ExposureOpen, AutomatableYes, HumanHigh, DecisionImmediate},
		{ExploitationActive, ExposureSmall, AutomatableNo, HumanLow, DecisionScheduled},
		{ExploitationNone, ExposureOpen, AutomatableYes, HumanVeryHigh, DecisionOutOfCycle},
		{ExploitationNone, ExposureSmall, AutomatableNo, HumanLow, DecisionDefer},
	}
	for _, c := range cases {
		if got := DeployerDecision(c.e, c.x, c.a, c.h); got != c.want {
			t.Errorf("%v = %s, want %s", c, got, c.want)
		}
	}
}

func TestExploitationPrecedence(t *testing.T) {
	t.Run("KEV is active but does not bypass context", func(t *testing.T) {
		f := explicit(newFinding(), "small", "no", "degraded", "negligible")
		f.Enrichment.InCISAKEV = true
		a := Assess(f)
		if a.Exploitation.Value != "active" || a.Decision != "scheduled" || a.Priority != "P3" {
			t.Errorf("got %s %s %s", a.Exploitation.Value, a.Decision, a.Priority)
		}
	})
	t.Run("KEV cannot be downgraded by analyst input", func(t *testing.T) {
		f := contextual()
		f.Enrichment.InCISAKEV = true
		f.SSVCInputs = map[string]string{"exploitation": "none", "automatable": "no"}
		a := Assess(f)
		e := a.Exploitation
		if e.Value != "active" || !e.Inferred || e.Source != "CISA KEV" || !e.NeedsConfirmation ||
			!strings.Contains(strings.Join(e.Evidence, " "), "cannot downgrade") {
			t.Errorf("exploitation = %+v", e)
		}
		if a.Automatable.Value != "no" || a.Automatable.Inferred {
			t.Errorf("automatable = %+v", a.Automatable)
		}
	})
	t.Run("analyst input without KEV is authoritative", func(t *testing.T) {
		f := contextual()
		f.SSVCInputs = map[string]string{"exploitation": "public_poc"}
		e := Assess(f).Exploitation
		if e.Value != "public_poc" || e.Inferred || e.Source != "analyst-confirmed SSVC input" {
			t.Errorf("exploitation = %+v", e)
		}
	})
	t.Run("analyst input outranks Vulnrichment", func(t *testing.T) {
		f := contextual()
		f.Enrichment.SSVCExploitation = strp("none")
		f.SSVCInputs = map[string]string{"exploitation": "active"}
		if e := Assess(f).Exploitation; e.Value != "active" || e.Inferred {
			t.Errorf("exploitation = %+v", e)
		}
	})
	t.Run("Vulnrichment poc when KEV is silent", func(t *testing.T) {
		f := contextual()
		f.Enrichment.SSVCExploitation = strp("poc")
		if e := Assess(f).Exploitation; e.Value != "public_poc" || e.Confidence != "high" || e.Source != "CISA Vulnrichment" {
			t.Errorf("exploitation = %+v", e)
		}
	})
	t.Run("KEV outranks a published none", func(t *testing.T) {
		f := contextual()
		f.Enrichment.InCISAKEV = true
		f.Enrichment.SSVCExploitation = strp("none")
		if e := Assess(f).Exploitation; e.Value != "active" || e.Source != "CISA KEV" {
			t.Errorf("exploitation = %+v", e)
		}
	})
	t.Run("local exploit references conflicting with none are surfaced", func(t *testing.T) {
		f := contextual()
		f.Enrichment.SSVCExploitation = strp("none")
		f.Enrichment.ExploitRefs = []string{"https://www.exploit-db.com/exploits/1"}
		e := Assess(f).Exploitation
		if e.Value != "public_poc" || !e.NeedsConfirmation || !strings.Contains(strings.Join(e.Evidence, " "), "disagree") {
			t.Errorf("exploitation = %+v", e)
		}
	})
	t.Run("public exploit reference sets public PoC", func(t *testing.T) {
		f := contextual()
		f.Enrichment.ExploitRefs = []string{"https://example.test/poc"}
		if e := Assess(f).Exploitation; e.Value != "public_poc" || e.Confidence != "medium" {
			t.Errorf("exploitation = %+v", e)
		}
	})
	t.Run("EPSS is supplemental, not observed exploitation", func(t *testing.T) {
		f := contextual()
		f.Enrichment.EPSSScore = f64p(0.99)
		a := Assess(f)
		if a.Exploitation.Value != "none" || a.Supplemental.EPSS == nil || *a.Supplemental.EPSS != 0.99 {
			t.Errorf("got %s %v", a.Exploitation.Value, a.Supplemental.EPSS)
		}
	})
	t.Run("no completed exploit search is low-confidence none", func(t *testing.T) {
		a := Assess(contextual())
		if strings.Join(a.NeedsConfirmation, ",") != "exploitation" || a.Exploitation.Confidence != "low" ||
			a.Confidence != "low" || a.SystemExposure.Confidence != "high" || a.MissionImpact.Confidence != "high" ||
			a.Priority != "P3" {
			t.Errorf("assessment = %+v", a)
		}
	})
	t.Run("completed exploit search supports medium-confidence none", func(t *testing.T) {
		f := contextual()
		f.Enrichment.ExploitSourcesChecked = []string{"nvd"}
		a := Assess(f)
		if a.Exploitation.Value != "none" || a.Exploitation.Confidence != "medium" ||
			a.Exploitation.NeedsConfirmation || len(a.NeedsConfirmation) != 0 {
			t.Errorf("assessment = %+v", a)
		}
	})
	t.Run("an NVD record proves the references were searched", func(t *testing.T) {
		f := contextual()
		f.Enrichment.NVDCVSSScore = f64p(7.5)
		e := Assess(f).Exploitation
		if e.Confidence != "medium" || !strings.Contains(e.Evidence[0], "nvd-record") {
			t.Errorf("exploitation = %+v", e)
		}
	})
}

func TestAutomatablePrecedence(t *testing.T) {
	unknown := Assess(explicit(newFinding(), "open", "unknown", "mef_failure", "marginal")).Automatable
	if unknown.Value != "yes" || !unknown.NeedsConfirmation || unknown.Confidence != "low" {
		t.Errorf("default = %+v", unknown)
	}
	published := explicit(newFinding(), "open", "unknown", "mef_failure", "marginal")
	published.Enrichment.SSVCAutomatable = strp("no")
	if a := Assess(published).Automatable; a.Value != "no" || a.NeedsConfirmation || a.Confidence != "high" || a.Source != "CISA Vulnrichment" {
		t.Errorf("published = %+v", a)
	}
	cvss4 := explicit(newFinding(), "open", "unknown", "mef_failure", "marginal")
	cvss4.Enrichment.NVDCVSSVector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/AU:N"
	if a := Assess(cvss4).Automatable; a.Value != "no" || a.Source != "CVSS v4 Automatable" {
		t.Errorf("cvss4 = %+v", a)
	}
	asset := explicit(newFinding(), "open", "no", "mef_failure", "marginal")
	asset.Enrichment.SSVCAutomatable = strp("yes")
	if a := Assess(asset).Automatable; a.Value != "no" || a.Source != "asset inventory" || a.Inferred {
		t.Errorf("asset = %+v", a)
	}
	analyst := explicit(newFinding(), "open", "no", "mef_failure", "marginal")
	analyst.SSVCInputs = map[string]string{"automatable": "yes"}
	if a := Assess(analyst).Automatable; a.Value != "yes" || a.Source != "analyst-confirmed SSVC input" {
		t.Errorf("analyst = %+v", a)
	}
}

func TestExposureMissionSafetyDefaults(t *testing.T) {
	a := Assess(newFinding())
	if a.SystemExposure.Value != "open" || a.Automatable.Value != "yes" ||
		a.MissionImpact.Value != "mef_support_crippled" || a.SafetyImpact.Value != "marginal" {
		t.Errorf("defaults = %+v", a)
	}
	got := append([]string(nil), a.NeedsConfirmation...)
	sort.Strings(got)
	if strings.Join(got, ",") != "automatable,exploitation,mission_impact,safety_impact,system_exposure" {
		t.Errorf("needs_confirmation = %v", got)
	}
	legacy := newFinding()
	legacy.Asset.InternetExposed = boolp(false)
	legacy.Asset.Criticality = "critical"
	b := Assess(legacy)
	if b.SystemExposure.Value != "controlled" || !b.SystemExposure.NeedsConfirmation ||
		b.MissionImpact.Value != "mef_failure" || b.MissionImpact.Confidence != "medium" {
		t.Errorf("legacy context = %+v / %+v", b.SystemExposure, b.MissionImpact)
	}
}

func TestTechnicalImpactNeverChangesTheDecision(t *testing.T) {
	baseline := contextual()
	baseline.Enrichment.SSVCExploitation, baseline.Enrichment.SSVCAutomatable = strp("active"), strp("yes")
	withImpact := contextual()
	withImpact.Enrichment.SSVCExploitation, withImpact.Enrichment.SSVCAutomatable = strp("active"), strp("yes")
	withImpact.Enrichment.SSVCTechnicalImpact = strp("total")
	b, w := Assess(baseline), Assess(withImpact)
	if w.TechnicalImpact.Value != "total" || w.TechnicalImpact.Confidence != "high" ||
		b.TechnicalImpact.Value != "unknown" || b.TechnicalImpact.Source != "not assessed" ||
		w.Decision != b.Decision || w.SuggestedDeadlineDays != b.SuggestedDeadlineDays || b.Confidence == "low" {
		t.Errorf("baseline %+v / with impact %+v", b, w)
	}
}

func TestActionSelection(t *testing.T) {
	cases := []struct {
		name, fixed string
		kev         bool
		context     [4]string
		want        string
	}{
		{"no fix keeps priority, mitigates", "", true, [4]string{"open", "yes", "mef_failure", "critical"}, "mitigate"},
		{"immediate with fix", "2.0", true, [4]string{"open", "yes", "mef_failure", "critical"}, "patch_immediately"},
		{"out of cycle with fix", "2.0", true, [4]string{"open", "no", "mef_failure", "marginal"}, "patch_out_of_cycle"},
		{"scheduled with fix", "2.0", false, [4]string{"open", "yes", "mef_failure", "marginal"}, "patch_scheduled"},
		{"scheduled without fix", "", false, [4]string{"open", "yes", "mef_failure", "marginal"}, "mitigate"},
		{"defer monitors", "", false, [4]string{"small", "no", "degraded", "negligible"}, "monitor"},
	}
	for _, c := range cases {
		f := explicit(newFinding(), c.context[0], c.context[1], c.context[2], c.context[3])
		f.Package.FixedVersion = c.fixed
		f.Enrichment.InCISAKEV = c.kev
		f.Enrichment.ExploitSourcesChecked = []string{"nvd"}
		if got := Assess(f).RecommendedAction; got != c.want {
			t.Errorf("%s: action = %s, want %s", c.name, got, c.want)
		}
	}
	noFix := explicit(newFinding(), "open", "yes", "mef_failure", "critical")
	noFix.Enrichment.InCISAKEV = true
	noFix.Package.FixedVersion = ""
	if a := Assess(noFix); a.Priority != "P1" {
		t.Errorf("a missing fix must not change the SSVC priority: %s", a.Priority)
	}
}

func TestTriageRecord(t *testing.T) {
	f := contextual()
	tr := Triage(f)
	if tr.Backend != "ssvc" || tr.Priority != tr.SSVC.Priority || tr.SuggestedDeadlineDays != 30 ||
		!strings.HasPrefix(tr.Rationale, "SSVC Deployer decision: E:None / EXP:Open / A:Yes / HI:Medium => Scheduled.") {
		t.Errorf("triage = %+v", tr)
	}
}

func TestOrderLessIsOrdinal(t *testing.T) {
	high := contextual()
	high.Enrichment.ExploitRefs = []string{"https://example.test/poc"} // public PoC, scheduled
	high.Enrichment.EPSSScore = f64p(0.01)
	low := contextual()
	low.Enrichment.EPSSScore = f64p(0.99)
	urgent := explicit(newFinding(), "open", "yes", "mef_failure", "critical")
	urgent.Enrichment.InCISAKEV = true
	findings := []*model.Finding{low, high, urgent}
	for _, f := range findings {
		f.Triage = Triage(f)
	}
	sort.SliceStable(findings, func(i, j int) bool { return OrderLess(findings[i], findings[j]) })
	if findings[0] != urgent || findings[1] != high || findings[2] != low {
		t.Errorf("order by priority then E before EPSS is wrong")
	}
}
