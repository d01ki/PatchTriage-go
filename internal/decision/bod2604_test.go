package decision

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/d01ki/PatchTriage-go/internal/model"
)

type bodRow struct {
	Row             int    `json:"row"`
	InKEV           string `json:"in_kev"`
	PubliclyExposed string `json:"publicly_exposed"`
	Automatable     string `json:"automatable"`
	TechnicalImpact string `json:"technical_impact"`
	OutcomeName     string `json:"outcome_name"`
	Outcome         string `json:"outcome"`
}

type bodExpectations struct {
	Model        string `json:"model"`
	OutcomeGroup string `json:"outcome_group"`
	Source       struct {
		CSV    string `json:"csv"`
		SHA256 string `json:"sha256"`
	} `json:"source"`
	Rows []bodRow `json:"rows"`
}

func expectations(t *testing.T) bodExpectations {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/bod2604_decision_table.json")
	if err != nil {
		t.Fatal(err)
	}
	var e bodExpectations
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}
	return e
}

type bodOpts struct {
	kevStatus, vulnrichment, applicability, publiclyExposed, systemExposure, mission, vector string
	inKEV                                                                                    bool
	automatable, technical, dateAdded                                                        *string
	internetExposed                                                                          *bool
}

func bodFinding(o bodOpts) *model.Finding {
	def := func(v, d string) string {
		if v == "" {
			return d
		}
		return v
	}
	f := &model.Finding{Key: "CVE-2024-0001|pkg|asset", VulnID: "CVE-2024-0001",
		Package: model.Package{Name: "pkg", Version: "1.2.3", FixedVersion: "1.2.4"}, Asset: model.NewAsset("asset")}
	f.Asset.InternetExposed = o.internetExposed
	f.Asset.SystemExposure = def(o.systemExposure, "unknown")
	f.Asset.MissionImpact = def(o.mission, "unknown")
	f.Asset.PubliclyExposed = def(o.publiclyExposed, "unknown")
	f.Asset.BOD2604Applicability = def(o.applicability, "unknown")
	f.Enrichment = model.Enrichment{InCISAKEV: o.inKEV, KEVDateAdded: o.dateAdded,
		SSVCAutomatable: o.automatable, SSVCTechnicalImpact: o.technical, NVDCVSSVector: o.vector,
		RetrievalStatus: map[string]string{"kev": o.kevStatus, "vulnrichment": def(o.vulnrichment, "found")}}
	if o.kevStatus == "" && !o.inKEV {
		f.Enrichment.RetrievalStatus["kev"] = "not_listed"
	}
	f.Triage = Triage(f)
	return f
}

func TestBODPinnedExpectationsMatchSourceFingerprint(t *testing.T) {
	e := expectations(t)
	sum := sha256.Sum256([]byte(e.Source.CSV))
	if hex.EncodeToString(sum[:]) != e.Source.SHA256 {
		t.Fatal("pinned CSV does not match its recorded SHA-256")
	}
	records, err := csv.NewReader(strings.NewReader(e.Source.CSV)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	for n, row := range e.Rows {
		got := []string{strconv.Itoa(row.Row), row.InKEV, row.PubliclyExposed, row.Automatable, row.TechnicalImpact, row.OutcomeName}
		if strings.Join(got, ",") != strings.Join(records[n+1], ",") {
			t.Errorf("row %d transcription %v != CSV %v", n, got, records[n+1])
		}
	}
	if e.Model != PolicyID || e.OutcomeGroup != OutcomeGroup {
		t.Errorf("model identity %s / %s", e.Model, e.OutcomeGroup)
	}
}

func TestBODAll16PublishedRowsMatch(t *testing.T) {
	rows := expectations(t).Rows
	seen := map[string]bool{}
	for _, r := range rows {
		seen[r.InKEV+r.PubliclyExposed+r.Automatable+r.TechnicalImpact] = true
		if got := BODOutcome(r.InKEV, r.PubliclyExposed, r.Automatable, r.TechnicalImpact); got != r.Outcome {
			t.Errorf("row %d: %s, published %s", r.Row, got, r.Outcome)
		}
	}
	if len(rows) != 16 || len(seen) != 16 {
		t.Errorf("rows %d, distinct combinations %d", len(rows), len(seen))
	}
}

func TestBODOnly3DFAddsForensicTriageAndFSUHasNoDeadline(t *testing.T) {
	days := map[string]int{"60D": 60, "14D": 14, "3D": 3, "3DF": 3}
	for key, outcome := range Outcomes {
		if contains(outcome.Obligations, "forensic_triage") != (key == "3DF") {
			t.Errorf("%s obligations %v", key, outcome.Obligations)
		}
		if key == "FSU" {
			if outcome.Days != nil {
				t.Error("FSU must have no numeric deadline")
			}
		} else if outcome.Days == nil || *outcome.Days != days[key] {
			t.Errorf("%s days %v", key, outcome.Days)
		}
	}
}

func TestBODResolvedInputsKeepSSVC(t *testing.T) {
	f := bodFinding(bodOpts{kevStatus: "listed", inKEV: true, automatable: strp("yes"), technical: strp("total"),
		publiclyExposed: "yes", applicability: "required", dateAdded: strp("2024-01-02")})
	before, _ := json.Marshal(f.Triage.SSVC)
	priority := f.Triage.Priority
	ApplyPolicy([]*model.Finding{f})
	p := f.Triage.BOD2604
	if p.Status != "resolved" || *p.Outcome != "3DF" || !contains(p.Obligations, "forensic_triage") ||
		p.KEVDateAdded != "2024-01-02" || !strings.Contains(p.DeadlineAnchor, "earlier of") {
		t.Errorf("policy = %+v", p)
	}
	raw, _ := json.Marshal(p)
	if strings.Contains(string(raw), "due_date\"") && !strings.Contains(string(raw), "kev_due_date") {
		t.Error("no absolute due date may be fabricated")
	}
	after, _ := json.Marshal(f.Triage.SSVC)
	if string(before) != string(after) || f.Triage.Priority != priority || f.Triage.Effective == nil {
		t.Error("BOD evaluation changed the SSVC record")
	}
}

func TestBODFailedKEVLookupNeverBecomesNotInKEV(t *testing.T) {
	p := EvaluateBOD(bodFinding(bodOpts{kevStatus: "failed", automatable: strp("yes"), technical: strp("total"), publiclyExposed: "yes"}))
	if p.Inputs.InKEV.Value != "unknown" || p.Status != "unresolved" || p.Outcome != nil ||
		strings.Join(p.CandidateOutcomes, ",") != "3DF,3D" || *p.ProvisionalOutcome != "3DF" ||
		!contains(p.UnresolvedInputs, "in_kev") {
		t.Errorf("policy = %+v", p)
	}
	for _, status := range []string{"unknown_stale", "not_applicable", "missing"} {
		f := bodFinding(bodOpts{kevStatus: status})
		if status == "missing" {
			delete(f.Enrichment.RetrievalStatus, "kev")
		}
		if EvaluateBOD(f).Inputs.InKEV.Resolved {
			t.Errorf("KEV status %q must stay unresolved", status)
		}
	}
}

func TestBODCISADefaultsOnlyWhenBothMissingAndNotInKEV(t *testing.T) {
	p := EvaluateBOD(bodFinding(bodOpts{vulnrichment: "not_found", publiclyExposed: "no"}))
	if p.Inputs.Automatable.Value != "no" || p.Inputs.TechnicalImpact.Value != "total" ||
		!p.Inputs.Automatable.Defaulted || *p.Outcome != "FSU" {
		t.Errorf("policy = %+v", p)
	}
	kev := EvaluateBOD(bodFinding(bodOpts{kevStatus: "listed", inKEV: true, vulnrichment: "not_found", publiclyExposed: "yes"}))
	cands := strings.Join(kev.CandidateOutcomes, ",")
	if kev.Inputs.Automatable.Value != "unknown" || kev.Inputs.TechnicalImpact.Value != "unknown" ||
		kev.Status != "unresolved" || cands != "3DF,3D,14D" {
		t.Errorf("KEV without Vulnrichment = %+v", kev)
	}
	failed := EvaluateBOD(bodFinding(bodOpts{vulnrichment: "failed", publiclyExposed: "no"}))
	if failed.Inputs.Automatable.Resolved || failed.Inputs.TechnicalImpact.Resolved {
		t.Error("a failed Vulnrichment lookup is not 'unpublished'")
	}
	one := EvaluateBOD(bodFinding(bodOpts{automatable: strp("yes"), publiclyExposed: "no"}))
	if one.Inputs.Automatable.Value != "yes" || one.Inputs.TechnicalImpact.Value != "unknown" ||
		one.Status != "resolved" || *one.Outcome != "60D" {
		t.Errorf("one published value = %+v", one)
	}
}

func TestBODPubliclyExposedIsNotSystemExposure(t *testing.T) {
	if v := EvaluateBOD(bodFinding(bodOpts{systemExposure: "open"})).Inputs.PubliclyExposed.Value; v != "unknown" {
		t.Errorf("open but unanswered = %s", v)
	}
	if v := EvaluateBOD(bodFinding(bodOpts{systemExposure: "small", publiclyExposed: "yes"})).Inputs.PubliclyExposed.Value; v != "yes" {
		t.Errorf("small but exposed = %s", v)
	}
	if v := EvaluateBOD(bodFinding(bodOpts{internetExposed: boolp(true)})).Inputs.PubliclyExposed.Value; v != "yes" {
		t.Errorf("internet exposure evidence = %s", v)
	}
	if v := EvaluateBOD(bodFinding(bodOpts{internetExposed: boolp(false)})).Inputs.PubliclyExposed.Value; v != "unknown" {
		t.Errorf("absent exposure evidence = %s", v)
	}
	if v := EvaluateBOD(bodFinding(bodOpts{publiclyExposed: "no", internetExposed: boolp(true)})).Inputs.PubliclyExposed.Value; v != "no" {
		t.Errorf("explicit answer = %s", v)
	}
}

func TestBODTechnicalImpactNotDerivedFromHumanImpact(t *testing.T) {
	if v := EvaluateBOD(bodFinding(bodOpts{mission: "mission_failure", vulnrichment: "failed"})).Inputs.TechnicalImpact.Value; v != "unknown" {
		t.Errorf("technical impact = %s", v)
	}
}

func TestBODCVSSv4AutomatableIsPublishedMetadata(t *testing.T) {
	p := EvaluateBOD(bodFinding(bodOpts{vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/AU:Y",
		technical: strp("partial"), publiclyExposed: "no"}))
	if p.Inputs.Automatable.Value != "yes" || p.Inputs.Automatable.Source != "CVSS v4 Automatable" {
		t.Errorf("automatable = %+v", p.Inputs.Automatable)
	}
}

func ssvcDays(days int, label string) *model.SSVCAssessment {
	return &model.SSVCAssessment{SuggestedDeadlineDays: days, DecisionLabel: label}
}

func policy(outcome, applicability, status string, unresolved ...string) model.BODResult {
	p := model.BODResult{Applicability: applicability, Applied: applicability == "required" || applicability == "voluntary",
		Status: status, UnresolvedInputs: unresolved}
	if status == "resolved" {
		p.Outcome = &outcome
	} else {
		p.ProvisionalOutcome = &outcome
	}
	return p
}

func TestResolveEffectiveRules(t *testing.T) {
	for _, applicability := range []string{"unknown", "not_applicable"} {
		e := ResolveEffective(ssvcDays(30, "Scheduled"), policy("3DF", applicability, "resolved"))
		if e.Rule != "ssvc_only" || *e.DeadlineDays != 30 || contains(e.Obligations, "forensic_triage") {
			t.Errorf("%s: %+v", applicability, e)
		}
	}
	if e := ResolveEffective(ssvcDays(30, "Scheduled"), policy("14D", "voluntary", "resolved")); e.Rule != "bod_maximum" || *e.DeadlineDays != 14 {
		t.Errorf("bod_maximum: %+v", e)
	}
	// Boundary: an equal workflow target still names the BOD maximum.
	if e := ResolveEffective(ssvcDays(3, "Immediate"), policy("3D", "required", "resolved")); e.Rule != "bod_maximum" || *e.DeadlineDays != 3 {
		t.Errorf("equal deadlines: %+v", e)
	}
	stricter := ResolveEffective(ssvcDays(1, "Immediate"), policy("3DF", "voluntary", "resolved"))
	if stricter.Rule != "workflow_target_stricter" || *stricter.DeadlineDays != 1 || !contains(stricter.Obligations, "forensic_triage") {
		t.Errorf("stricter: %+v", stricter)
	}
	fsu := ResolveEffective(ssvcDays(90, "Defer"), policy("FSU", "voluntary", "resolved"))
	if fsu.Rule != "bod_fix_on_upgrade" || *fsu.DeadlineDays != 90 || fsu.DeadlineSource != "SSVC workflow target" ||
		!contains(fsu.Obligations, "remediate_at_next_major_upgrade") {
		t.Errorf("FSU: %+v", fsu)
	}
	provisional := ResolveEffective(ssvcDays(30, "Scheduled"), policy("3DF", "voluntary", "unresolved", "in_kev"))
	if provisional.Rule != "bod_unresolved_provisional" || !provisional.RequiresConfirmation ||
		*provisional.DeadlineDays != 3 || !strings.Contains(provisional.Explanation, "Provisional") {
		t.Errorf("provisional: %+v", provisional)
	}
	if e := ResolveEffective(nil, policy("FSU", "voluntary", "resolved")); e.DeadlineDays != nil || e.SSVCWorkflowDays != nil {
		t.Errorf("missing SSVC record: %+v", e)
	}
}

func TestBODRequiredAndVoluntaryAreDistinguished(t *testing.T) {
	required := EvaluateBOD(bodFinding(bodOpts{applicability: "required"}))
	voluntary := EvaluateBOD(bodFinding(bodOpts{applicability: "voluntary"}))
	if !required.Applied || !voluntary.Applied || !strings.Contains(required.ApplicabilityNote, "binding") ||
		!strings.Contains(voluntary.ApplicabilityNote, "not a legal obligation") {
		t.Errorf("required %+v / voluntary %+v", required, voluntary)
	}
}

func TestSummarizePolicy(t *testing.T) {
	resolved := bodFinding(bodOpts{kevStatus: "listed", inKEV: true, automatable: strp("yes"), technical: strp("total"),
		publiclyExposed: "yes", applicability: "voluntary"})
	unresolved := bodFinding(bodOpts{kevStatus: "failed"})
	untriaged := &model.Finding{}
	ApplyPolicy([]*model.Finding{resolved, unresolved, untriaged})
	s := SummarizePolicy([]*model.Finding{resolved, unresolved, untriaged})
	outcomes := s["outcomes"].(map[string]int)
	if s["evaluated"] != 2 || s["resolved"] != 1 || s["unresolved"] != 1 || outcomes["3DF"] != 1 ||
		s["forensic_triage"] != 2 || s["applied"] != true ||
		strings.Join(s["applicability"].([]string), ",") != "unknown,voluntary" {
		t.Errorf("summary = %v", s)
	}
}
