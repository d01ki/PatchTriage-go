package pipeline

// Human-facing labels and evidence summaries for triage decisions.

import (
	"bytes"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"github.com/d01ki/PatchTriage-go/internal/model"
)

var priorityDefinitions = map[string]map[string]string{
	"P1": {"label": "Immediate", "ssvc_outcome": "Immediate",
		"description": "SSVC calls for immediate action with all necessary resources.", "window": "3 days"},
	"P2": {"label": "Out-of-Cycle", "ssvc_outcome": "Out-of-Cycle",
		"description": "Act at the next available opportunity outside normal maintenance.", "window": "14 days"},
	"P3": {"label": "Scheduled", "ssvc_outcome": "Scheduled",
		"description": "Handle during regularly scheduled maintenance.", "window": "30 days"},
	"P4": {"label": "Defer", "ssvc_outcome": "Defer",
		"description": "Do not act at present; monitor the evidence and reassess changes.", "window": "90 days"},
}

// Sources that represent a published or recorded judgement rather than a
// PatchTriage fallback.
var authoritativeSources = map[string]bool{
	"CISA KEV": true, "CISA Vulnrichment": true, "analyst-confirmed SSVC input": true,
	"asset inventory": true, "CVSS v4 Automatable": true,
}

// PriorityDefinition returns the human definition of a priority code.
func PriorityDefinition(priority string) map[string]string {
	code := priority
	if _, ok := priorityDefinitions[code]; !ok {
		code = "P4"
	}
	out := map[string]string{"code": code}
	for k, v := range priorityDefinitions[code] {
		out[k] = v
	}
	return out
}

// Counts is an insertion-ordered name -> count map that marshals as an
// ordered JSON object.
type Counts []struct {
	Key   string
	Count int
}

// Get returns the count for key (0 when absent).
func (c Counts) Get(key string) int {
	for _, item := range c {
		if item.Key == key {
			return item.Count
		}
	}
	return 0
}

func (c Counts) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for n, item := range c {
		if n > 0 {
			b.WriteByte(',')
		}
		key, _ := json.Marshal(item.Key)
		b.Write(key)
		b.WriteString(":" + strconv.Itoa(item.Count))
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

func (c *Counts) add(key string) {
	for n := range *c {
		if (*c)[n].Key == key {
			(*c)[n].Count++
			return
		}
	}
	*c = append(*c, struct {
		Key   string
		Count int
	}{key, 1})
}

// DecisionQuality summarizes how much of a run rests on authority versus
// assumption. Only the two vulnerability-specific points are counted; the
// target context can only come from the operator. de_escalated counts
// findings where a published assessment is less urgent than the
// conservative default.
func DecisionQuality(findings []*model.Finding) map[string]any {
	var sources Counts
	assessed, authoritative, deEscalated, needsConfirmation := 0, 0, 0, 0
	for _, f := range findings {
		if f.Triage == nil || f.Triage.SSVC == nil {
			continue
		}
		s := f.Triage.SSVC
		assessed++
		if len(s.NeedsConfirmation) > 0 {
			needsConfirmation++
		}
		for _, p := range []model.DecisionPoint{s.Exploitation, s.Automatable} {
			if p.Source == "" {
				continue
			}
			sources.add(p.Source)
			if authoritativeSources[p.Source] {
				authoritative++
			}
		}
		if s.Automatable.Source == "CISA Vulnrichment" && s.Automatable.Value == "no" {
			deEscalated++
		}
	}
	sort.SliceStable(sources, func(i, j int) bool { return sources[i].Count > sources[j].Count })
	if sources == nil {
		sources = Counts{}
	}
	total := assessed * 2
	pct := 0.0
	if total > 0 {
		pct = pyRound(float64(authoritative)/float64(total)*100, 1)
	}
	return map[string]any{
		"findings": assessed, "points_total": total, "authoritative": authoritative,
		"assumed": total - authoritative, "authoritative_pct": pct,
		"needs_confirmation": needsConfirmation, "de_escalated": deEscalated, "sources": sources,
	}
}

func ssvcOf(f *model.Finding) *model.SSVCAssessment {
	if f.Triage == nil {
		return nil
	}
	return f.Triage.SSVC
}

// PriorityEvidence presents the SSVC decision points without a parallel
// score model.
func PriorityEvidence(f *model.Finding) []map[string]string {
	s := ssvcOf(f)
	if s == nil {
		s = &model.SSVCAssessment{}
	}
	var checks []map[string]string
	for _, p := range []struct {
		label string
		point model.DecisionPoint
	}{{"Exploitation", s.Exploitation}, {"System Exposure", s.SystemExposure},
		{"Automatable", s.Automatable}, {"Human Impact", s.HumanImpact}} {
		confidence, label := p.point.Confidence, p.point.Label
		if confidence == "" {
			confidence = "low"
		}
		if label == "" {
			label = "Unknown"
		}
		status := "attention"
		if confidence == "high" {
			status = "confirmed"
		}
		evidence := strings.Join(p.point.Evidence, "; ")
		if evidence == "" {
			evidence = "evidence missing"
		}
		checks = append(checks, map[string]string{"label": p.label, "status": status,
			"value": label + " · " + evidence + " (" + confidence + " confidence)"})
	}
	// Technical Impact is not a Deployer input: supporting evidence only.
	if ti := s.TechnicalImpact; ti != nil {
		status := "unknown"
		if ti.Value != "" && ti.Value != "unknown" {
			status = "confirmed"
		}
		evidence := strings.Join(ti.Evidence, "; ")
		if evidence == "" {
			evidence = "not published for this CVE"
		}
		label := ti.Label
		if label == "" {
			label = "Unknown"
		}
		checks = append(checks, map[string]string{"label": "Technical Impact", "status": status,
			"value": label + " · " + evidence + " (not an input to the Deployer decision)"})
	}
	if f.Package.FixedVersion != "" {
		checks = append(checks, map[string]string{"label": "Fix readiness", "status": "confirmed",
			"value": "Fixed version " + f.Package.FixedVersion + " is available"})
	} else {
		checks = append(checks, map[string]string{"label": "Fix readiness", "status": "attention",
			"value": "No fixed version supplied; mitigate or investigate"})
	}
	return checks
}

// PriorityBasis explains the deterministic SSVC path behind a priority.
func PriorityBasis(f *model.Finding) string {
	if s := ssvcOf(f); s != nil && s.DecisionPath != "" {
		label := s.DecisionLabel
		if label == "" {
			label = "this decision"
		}
		return "The SSVC Deployer path " + s.DecisionPath + " results in " + label + "."
	}
	return "This result is missing its SSVC decision path; rerun triage before relying on this recommendation."
}

// EvaluationOutcome translates one evaluation row into user-facing measures.
func EvaluationOutcome(row EvalRow, totalFindings int) map[string]any {
	reviewed := min(row.K, totalFindings)
	ratio := func(a, b int) float64 {
		if b == 0 {
			return 0
		}
		return float64(a) / float64(b) * 100
	}
	reduction := 0.0
	if totalFindings > 0 {
		reduction = (1 - float64(reviewed)/float64(totalFindings)) * 100
	}
	ssvcCoverage, cvssCoverage := ratio(row.KEVSSVC, row.KEVTotal), ratio(row.KEVBaseline, row.KEVTotal)
	var lift any
	if row.KEVBaseline != 0 {
		lift = pyRound(float64(row.KEVSSVC)/float64(row.KEVBaseline), 1)
	}
	return map[string]any{
		"reviewed": reviewed, "review_reduction_pct": pyRound(reduction, 1),
		"kev_coverage_pct": pyRound(ssvcCoverage, 1), "kev_gain_points": pyRound(ssvcCoverage-cvssCoverage, 1),
		"additional_kev_vs_cvss": row.KEVSSVC - row.KEVBaseline, "kev_lift_vs_cvss": lift,
		"urgent_coverage_pct": pyRound(ratio(row.UrgentSSVC, row.UrgentTotal), 1),
	}
}
