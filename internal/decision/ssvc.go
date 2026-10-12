// Package decision holds PatchTriage's deterministic decision models: the
// CERT/CC SSVC Deployer tree (ssvc:DT_DP:1.0.0) and, separately, the CISA
// BOD 26-04 response policy (cisa:DT_BOD2604:1.0.0).
//
// PatchTriage is a deployer: it decides how quickly to apply a remediation
// in this environment. Every decision point keeps its provenance. KEV and
// exploit references inform Exploitation; EPSS stays supplemental evidence
// and is never converted into an observed exploitation state.
package decision

import (
	"fmt"
	"sort"
	"strings"

	"github.com/d01ki/PatchTriage-go/internal/model"
)

// Model is the pinned SSVC decision model identity.
const Model = "ssvc:DT_DP:1.0.0"

type (
	Exploitation    string
	SystemExposure  string
	Automatable     string
	MissionImpact   string
	SafetyImpact    string
	HumanImpact     string
	TechnicalImpact string
	Decision        string
	confidence      string
)

const (
	ExploitationNone   Exploitation = "none"
	ExploitationPoC    Exploitation = "public_poc"
	ExploitationActive Exploitation = "active"

	ExposureSmall      SystemExposure = "small"
	ExposureControlled SystemExposure = "controlled"
	ExposureOpen       SystemExposure = "open"

	AutomatableNo  Automatable = "no"
	AutomatableYes Automatable = "yes"

	MissionDegraded        MissionImpact = "degraded"
	MissionSupportCrippled MissionImpact = "mef_support_crippled"
	MissionMEFFailure      MissionImpact = "mef_failure"
	MissionFailure         MissionImpact = "mission_failure"

	SafetyNegligible   SafetyImpact = "negligible"
	SafetyMarginal     SafetyImpact = "marginal"
	SafetyCritical     SafetyImpact = "critical"
	SafetyCatastrophic SafetyImpact = "catastrophic"

	HumanLow      HumanImpact = "low"
	HumanMedium   HumanImpact = "medium"
	HumanHigh     HumanImpact = "high"
	HumanVeryHigh HumanImpact = "very_high"

	TechnicalPartial TechnicalImpact = "partial"
	TechnicalTotal   TechnicalImpact = "total"
	TechnicalUnknown TechnicalImpact = "unknown"

	DecisionDefer      Decision = "defer"
	DecisionScheduled  Decision = "scheduled"
	DecisionOutOfCycle Decision = "out_of_cycle"
	DecisionImmediate  Decision = "immediate"

	confidenceHigh   confidence = "high"
	confidenceMedium confidence = "medium"
	confidenceLow    confidence = "low"
)

// Ordered value lists for every decision point.
var (
	Exploitations   = []Exploitation{ExploitationNone, ExploitationPoC, ExploitationActive}
	SystemExposures = []SystemExposure{ExposureSmall, ExposureControlled, ExposureOpen}
	Automatables    = []Automatable{AutomatableNo, AutomatableYes}
	MissionImpacts  = []MissionImpact{MissionDegraded, MissionSupportCrippled, MissionMEFFailure, MissionFailure}
	SafetyImpacts   = []SafetyImpact{SafetyNegligible, SafetyMarginal, SafetyCritical, SafetyCatastrophic}
	HumanImpacts    = []HumanImpact{HumanLow, HumanMedium, HumanHigh, HumanVeryHigh}
)

var labels = map[string]string{
	"none": "None", "public_poc": "Public PoC", "active": "Active",
	"small": "Small", "controlled": "Controlled", "open": "Open",
	"no": "No", "yes": "Yes",
	"degraded": "Degraded", "mef_support_crippled": "MEF Support Crippled",
	"mef_failure": "MEF Failure", "mission_failure": "Mission Failure",
	"negligible": "Negligible", "marginal": "Marginal", "critical": "Critical", "catastrophic": "Catastrophic",
	"low": "Low", "medium": "Medium", "high": "High", "very_high": "Very High",
	"partial": "Partial", "total": "Total", "unknown": "Unknown",
	"defer": "Defer", "scheduled": "Scheduled", "out_of_cycle": "Out-of-Cycle", "immediate": "Immediate",
}

// LabelFor returns the official display label of a value, or the value.
func LabelFor(value string) string {
	if label, ok := labels[value]; ok {
		return label
	}
	return value
}

// CISA publishes Vulnrichment decision points with its own spelling.
var (
	vulnrichmentExploitation = map[string]Exploitation{"none": ExploitationNone, "poc": ExploitationPoC, "active": ExploitationActive}
	vulnrichmentAutomatable  = map[string]Automatable{"yes": AutomatableYes, "no": AutomatableNo}
	vulnrichmentTechnical    = map[string]TechnicalImpact{"partial": TechnicalPartial, "total": TechnicalTotal}
)

// humanImpactTable is the official Human Impact v2.0.2 table; all 16 rows
// are explicit so the prose summary is never treated as a formula.
var humanImpactTable = map[SafetyImpact][4]HumanImpact{ // by Mission Impact order
	SafetyNegligible:   {HumanLow, HumanLow, HumanMedium, HumanVeryHigh},
	SafetyMarginal:     {HumanLow, HumanLow, HumanMedium, HumanVeryHigh},
	SafetyCritical:     {HumanMedium, HumanHigh, HumanHigh, HumanVeryHigh},
	SafetyCatastrophic: {HumanVeryHigh, HumanVeryHigh, HumanVeryHigh, HumanVeryHigh},
}

type deployerKey struct {
	e Exploitation
	x SystemExposure
	a Automatable
}

const (
	d = DecisionDefer
	s = DecisionScheduled
	o = DecisionOutOfCycle
	i = DecisionImmediate
)

// deployerTable is the official SSVC Deployer table: one row per
// Exploitation / Exposure / Automatable path, columns by Human Impact
// (Low, Medium, High, Very High).
var deployerTable = map[deployerKey][4]Decision{
	{ExploitationNone, ExposureSmall, AutomatableNo}:         {d, d, s, s},
	{ExploitationNone, ExposureSmall, AutomatableYes}:        {d, s, s, s},
	{ExploitationNone, ExposureControlled, AutomatableNo}:    {d, s, s, s},
	{ExploitationNone, ExposureControlled, AutomatableYes}:   {s, s, s, s},
	{ExploitationNone, ExposureOpen, AutomatableNo}:          {d, s, s, s},
	{ExploitationNone, ExposureOpen, AutomatableYes}:         {s, s, s, o},
	{ExploitationPoC, ExposureSmall, AutomatableNo}:          {d, s, s, s},
	{ExploitationPoC, ExposureSmall, AutomatableYes}:         {s, s, s, s},
	{ExploitationPoC, ExposureControlled, AutomatableNo}:     {d, s, s, s},
	{ExploitationPoC, ExposureControlled, AutomatableYes}:    {s, s, s, o},
	{ExploitationPoC, ExposureOpen, AutomatableNo}:           {s, s, s, o},
	{ExploitationPoC, ExposureOpen, AutomatableYes}:          {s, s, o, o},
	{ExploitationActive, ExposureSmall, AutomatableNo}:       {s, s, o, o},
	{ExploitationActive, ExposureSmall, AutomatableYes}:      {s, o, o, o},
	{ExploitationActive, ExposureControlled, AutomatableNo}:  {s, s, o, o},
	{ExploitationActive, ExposureControlled, AutomatableYes}: {o, o, o, o},
	{ExploitationActive, ExposureOpen, AutomatableNo}:        {s, o, o, i},
	{ExploitationActive, ExposureOpen, AutomatableYes}:       {o, o, i, i},
}

// decisionPolicy holds PatchTriage's workflow targets; they are not SSVC values.
var decisionPolicy = map[Decision]struct {
	priority string
	days     int
}{
	DecisionImmediate: {"P1", 3}, DecisionOutOfCycle: {"P2", 14},
	DecisionScheduled: {"P3", 30}, DecisionDefer: {"P4", 90},
}

var confidenceRank = map[string]int{"low": 0, "medium": 1, "high": 2}

func index[T comparable](values []T, value T) int {
	for n, v := range values {
		if v == value {
			return n
		}
	}
	return -1
}

func contains[T comparable](values []T, value T) bool { return index(values, value) >= 0 }

// DeriveHumanImpact applies the official Human Impact v2.0.2 table.
func DeriveHumanImpact(m MissionImpact, s SafetyImpact) HumanImpact {
	return humanImpactTable[s][index(MissionImpacts, m)]
}

// DeployerDecision looks up one fully specified Deployer path.
func DeployerDecision(e Exploitation, x SystemExposure, a Automatable, h HumanImpact) Decision {
	return deployerTable[deployerKey{e, x, a}][index(HumanImpacts, h)]
}

// HumanImpactBranches lists what each Human Impact value yields below one
// Deployer path, read straight from the official table.
func HumanImpactBranches(e, x, a string) []map[string]string {
	row := deployerTable[deployerKey{Exploitation(e), SystemExposure(x), Automatable(a)}]
	out := make([]map[string]string, 0, len(HumanImpacts))
	for n, h := range HumanImpacts {
		out = append(out, map[string]string{
			"human_impact": string(h), "human_impact_label": LabelFor(string(h)),
			"decision": string(row[n]), "decision_label": LabelFor(string(row[n])),
		})
	}
	return out
}

func point(key, version, value string, c confidence, source string, evidence []string, inferred, needsConfirmation bool) model.DecisionPoint {
	return model.DecisionPoint{Key: key, Version: version, Value: value, Label: labels[value],
		Confidence: string(c), Source: source, Evidence: evidence, Inferred: inferred, NeedsConfirmation: needsConfirmation}
}

func lowerPtr(v *string) string {
	if v == nil {
		return ""
	}
	return strings.ToLower(*v)
}

func timestamped(evidence []string, timestamp string) []string {
	if timestamp != "" {
		evidence = append(evidence, "CISA assessment timestamp "+timestamp)
	}
	return evidence
}

func inferExploitation(f *model.Finding) model.DecisionPoint {
	explicit := f.SSVCInputs["exploitation"]
	e := f.Enrichment
	if e.InCISAKEV {
		evidence := []string{"CISA KEV confirms exploitation in the wild"}
		if e.KEVRansomware {
			evidence = append(evidence, "CISA KEV reports ransomware campaign use")
		}
		conflict := explicit == string(ExploitationNone) || explicit == string(ExploitationPoC)
		if conflict {
			evidence = append(evidence, "Analyst input conflicts with CISA KEV and cannot downgrade "+
				"Active exploitation to "+labels[explicit])
		} else if explicit == string(ExploitationActive) {
			evidence = append(evidence, "Analyst-confirmed input agrees with CISA KEV")
		}
		return point("E", "1.1.0", "active", confidenceHigh, "CISA KEV", evidence, true, conflict)
	}
	if contains(Exploitations, Exploitation(explicit)) {
		return point("E", "1.1.0", explicit, confidenceHigh, "analyst-confirmed SSVC input",
			[]string{"Exploitation confirmed as " + labels[explicit]}, false, false)
	}
	if published, ok := vulnrichmentExploitation[lowerPtr(e.SSVCExploitation)]; ok {
		evidence := timestamped([]string{"CISA Vulnrichment publishes Exploitation as " + labels[string(published)]}, e.SSVCTimestamp)
		if published == ExploitationNone && len(e.ExploitRefs) > 0 {
			// An authoritative "none" must not silently bury contradicting
			// local evidence; surface both and ask for a human decision.
			evidence = append(evidence, fmt.Sprintf("%d public exploit reference(s) were "+
				"also found and disagree with the published assessment", len(e.ExploitRefs)))
			return point("E", "1.1.0", "public_poc", confidenceMedium,
				"public exploit references (conflicts with CISA Vulnrichment)", evidence, true, true)
		}
		return point("E", "1.1.0", string(published), confidenceHigh, "CISA Vulnrichment", evidence, true, false)
	}
	if len(e.ExploitRefs) > 0 {
		return point("E", "1.1.0", "public_poc", confidenceMedium, "public exploit references",
			[]string{fmt.Sprintf("%d public exploit reference(s) found", len(e.ExploitRefs))}, true, false)
	}
	coverage := uniqueSorted(e.ExploitSourcesChecked)
	// A retrieved NVD record proves its references were searched; generic
	// provenance (timestamps, EPSS) does not.
	if len(coverage) == 0 && (e.NVDCVSSScore != nil || e.NVDCVSSVector != "" || len(e.CWEIDs) > 0) {
		coverage = []string{"nvd-record"}
	}
	if len(coverage) > 0 {
		return point("E", "1.1.0", "none", confidenceMedium, "exploit-source coverage",
			[]string{"No active exploitation or public PoC evidence was found in: " + strings.Join(coverage, ", ")}, true, false)
	}
	return point("E", "1.1.0", "none", confidenceLow, "unconfirmed default",
		[]string{"No completed exploit-source search is recorded; absence of evidence is not evidence of absence"}, true, true)
}

func uniqueSorted(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range values {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

func inferSystemExposure(a model.Asset) model.DecisionPoint {
	if contains(SystemExposures, SystemExposure(a.SystemExposure)) {
		return point("EXP", "1.0.1", a.SystemExposure, confidenceHigh, "asset inventory",
			[]string{"System exposure confirmed as " + labels[a.SystemExposure]}, false, false)
	}
	if a.InternetExposed != nil && *a.InternetExposed {
		return point("EXP", "1.0.1", "open", confidenceMedium, "legacy internet_exposed context",
			[]string{"Asset is marked internet-exposed"}, true, true)
	}
	if a.InternetExposed != nil {
		return point("EXP", "1.0.1", "controlled", confidenceMedium, "legacy internet_exposed context",
			[]string{"Asset is marked non-internet-facing; access controls are not described"}, true, true)
	}
	return point("EXP", "1.0.1", "open", confidenceLow, "SSVC conservative default",
		[]string{"Exposure is unknown; SSVC recommends assuming Open"}, true, true)
}

func cvssMetrics(vector string) map[string]string {
	metrics := map[string]string{}
	for _, part := range strings.Split(strings.ToUpper(vector), "/") {
		if key, value, ok := strings.Cut(part, ":"); ok {
			metrics[key] = value
		}
	}
	return metrics
}

func inferAutomatable(f *model.Finding) model.DecisionPoint {
	if explicit := f.SSVCInputs["automatable"]; contains(Automatables, Automatable(explicit)) {
		return point("A", "2.0.0", explicit, confidenceHigh, "analyst-confirmed SSVC input",
			[]string{"Automatable confirmed as " + labels[explicit]}, false, false)
	}
	if contains(Automatables, Automatable(f.Asset.Automatable)) {
		return point("A", "2.0.0", f.Asset.Automatable, confidenceHigh, "asset inventory",
			[]string{"Automatable confirmed as " + labels[f.Asset.Automatable]}, false, false)
	}
	e := f.Enrichment
	if published, ok := vulnrichmentAutomatable[lowerPtr(e.SSVCAutomatable)]; ok {
		return point("A", "2.0.0", string(published), confidenceHigh, "CISA Vulnrichment",
			timestamped([]string{"CISA Vulnrichment publishes Automatable as " + labels[string(published)]}, e.SSVCTimestamp), true, false)
	}
	if au := cvssMetrics(e.NVDCVSSVector)["AU"]; au == "Y" || au == "N" {
		value := "no"
		if au == "Y" {
			value = "yes"
		}
		return point("A", "2.0.0", value, confidenceHigh, "CVSS v4 Automatable",
			[]string{"CVSS vector contains AU:" + au}, true, false)
	}
	return point("A", "2.0.0", "yes", confidenceLow, "SSVC conservative default",
		[]string{"Automation evidence is unknown; SSVC recommends assuming Yes"}, true, true)
}

// inferTechnicalImpact records CISA's published Technical Impact or an
// explicit Unknown. It is supplemental: the Deployer tree never consumes it.
func inferTechnicalImpact(e model.Enrichment) model.DecisionPoint {
	if published, ok := vulnrichmentTechnical[lowerPtr(e.SSVCTechnicalImpact)]; ok {
		return point("TI", "1.0.0", string(published), confidenceHigh, "CISA Vulnrichment",
			timestamped([]string{"CISA Vulnrichment publishes Technical Impact as " + labels[string(published)]}, e.SSVCTimestamp), true, false)
	}
	return point("TI", "1.0.0", "unknown", confidenceLow, "not assessed",
		[]string{"No published Technical Impact assessment was found for this CVE"}, true, false)
}

var criticalityMission = map[string]MissionImpact{
	"critical": MissionMEFFailure, "high": MissionSupportCrippled, "medium": MissionDegraded, "low": MissionDegraded,
}

func inferMissionImpact(a model.Asset) model.DecisionPoint {
	if contains(MissionImpacts, MissionImpact(a.MissionImpact)) {
		return point("MI", "2.0.0", a.MissionImpact, confidenceHigh, "asset inventory",
			[]string{"Mission impact confirmed as " + labels[a.MissionImpact]}, false, false)
	}
	if mapped, ok := criticalityMission[a.Criticality]; ok {
		return point("MI", "2.0.0", string(mapped), confidenceMedium, "business criticality fallback",
			[]string{fmt.Sprintf("Legacy criticality '%s' maps to %s", a.Criticality, labels[string(mapped)])}, true, true)
	}
	return point("MI", "2.0.0", "mef_support_crippled", confidenceLow, "SSVC conservative default",
		[]string{"Mission impact is unknown; SSVC recommends MEF Support Crippled"}, true, true)
}

func inferSafetyImpact(a model.Asset) model.DecisionPoint {
	if contains(SafetyImpacts, SafetyImpact(a.SafetyImpact)) {
		return point("SI", "2.0.1", a.SafetyImpact, confidenceHigh, "asset inventory",
			[]string{"Safety impact confirmed as " + labels[a.SafetyImpact]}, false, false)
	}
	return point("SI", "2.0.1", "marginal", confidenceLow, "SSVC conservative default",
		[]string{"Safety impact is unknown; SSVC recommends assuming Marginal"}, true, true)
}

func minConfidence(points ...model.DecisionPoint) string {
	lowest := points[0].Confidence
	for _, p := range points[1:] {
		if confidenceRank[p.Confidence] < confidenceRank[lowest] {
			lowest = p.Confidence
		}
	}
	return lowest
}

// cvssOf mirrors Python's `nvd_cvss_score or cvss_score` (0.0 is falsy).
func cvssOf(f *model.Finding) *float64 {
	if f.Enrichment.NVDCVSSScore != nil && *f.Enrichment.NVDCVSSScore != 0 {
		return f.Enrichment.NVDCVSSScore
	}
	return f.CVSSScore
}

// Assess computes the deterministic SSVC Deployer decision for a finding.
func Assess(f *model.Finding) model.SSVCAssessment {
	exploitation := inferExploitation(f)
	exposure := inferSystemExposure(f.Asset)
	automatable := inferAutomatable(f)
	technical := inferTechnicalImpact(f.Enrichment)
	mission := inferMissionImpact(f.Asset)
	safety := inferSafetyImpact(f.Asset)
	humanValue := DeriveHumanImpact(MissionImpact(mission.Value), SafetyImpact(safety.Value))
	human := point("HI", "2.0.2", string(humanValue), confidence(minConfidence(mission, safety)),
		"SSVC Human Impact table", []string{mission.Label + " mission impact + " + safety.Label + " safety impact"},
		true, mission.NeedsConfirmation || safety.NeedsConfirmation)
	decision := DeployerDecision(Exploitation(exploitation.Value), SystemExposure(exposure.Value),
		Automatable(automatable.Value), humanValue)
	policy := decisionPolicy[decision]

	hasFix := f.Package.FixedVersion != ""
	var action string
	switch {
	case !hasFix && decision != DecisionDefer:
		action = "mitigate"
	case decision == DecisionImmediate:
		action = "patch_immediately"
	case decision == DecisionOutOfCycle:
		action = "patch_out_of_cycle"
	case decision == DecisionScheduled && hasFix:
		action = "patch_scheduled"
	case decision == DecisionScheduled:
		action = "investigate"
	default:
		action = "monitor"
	}

	confirmation := []string{}
	for _, named := range []struct {
		name  string
		point model.DecisionPoint
	}{{"exploitation", exploitation}, {"system_exposure", exposure}, {"automatable", automatable},
		{"mission_impact", mission}, {"safety_impact", safety}} {
		if named.point.NeedsConfirmation {
			confirmation = append(confirmation, named.name)
		}
	}
	path := fmt.Sprintf("E:%s / EXP:%s / A:%s / HI:%s", exploitation.Label, exposure.Label, automatable.Label, human.Label)
	return model.SSVCAssessment{
		Model: Model, Exploitation: exploitation, SystemExposure: exposure, Automatable: automatable,
		MissionImpact: mission, SafetyImpact: safety, HumanImpact: human, TechnicalImpact: &technical,
		Decision: string(decision), DecisionLabel: labels[string(decision)], Priority: policy.priority,
		SuggestedDeadlineDays: policy.days, RecommendedAction: action,
		Confidence:        minConfidence(exploitation, exposure, automatable, mission, safety, human),
		NeedsConfirmation: confirmation, DecisionPath: path,
		Rationale: fmt.Sprintf("SSVC Deployer decision: %s => %s. PatchTriage's example service target is %d days; "+
			"the SSVC standard itself defines the categorical outcome, not this deadline.", path, labels[string(decision)], policy.days),
		Supplemental: model.Supplemental{KEV: f.Enrichment.InCISAKEV, EPSS: f.Enrichment.EPSSScore,
			CVSS: cvssOf(f), Reachable: f.Asset.Reachable, RuntimeObserved: f.Asset.RuntimeObserved},
	}
}

// Triage returns the deterministic decision record for a finding.
func Triage(f *model.Finding) *model.Triage {
	a := Assess(f)
	return &model.Triage{Priority: a.Priority, Action: a.RecommendedAction, Rationale: a.Rationale,
		SuggestedDeadlineDays: a.SuggestedDeadlineDays, Backend: "ssvc", SSVC: &a}
}

var (
	exploitationRank = map[string]float64{"none": 0, "public_poc": 1, "active": 2}
	humanRank        = map[string]float64{"low": 0, "medium": 1, "high": 2, "very_high": 3}
	exposureRank     = map[string]float64{"small": 0, "controlled": 1, "open": 2}
	priorityRank     = map[string]int{"P1": 0, "P2": 1, "P3": 2, "P4": 3}
)

// SortKey is the ordinal-only tie-break key for findings in one priority:
// each decision point is compared in order and never combined into a score.
func SortKey(f *model.Finding) [6]float64 {
	var a model.SSVCAssessment
	if f.Triage != nil && f.Triage.SSVC != nil {
		a = *f.Triage.SSVC
	} else {
		a = Assess(f)
	}
	automatable := 0.0
	if a.Automatable.Value == "yes" {
		automatable = 1
	}
	key := [6]float64{exploitationRank[a.Exploitation.Value], humanRank[a.HumanImpact.Value],
		exposureRank[a.SystemExposure.Value], automatable}
	if f.Enrichment.EPSSScore != nil {
		key[4] = *f.Enrichment.EPSSScore
	}
	if cvss := cvssOf(f); cvss != nil {
		key[5] = *cvss
	}
	return key
}

// PriorityRank orders P1..P4 (unknown priorities last).
func PriorityRank(priority string) int {
	if rank, ok := priorityRank[priority]; ok {
		return rank
	}
	return 9
}

func priorityOf(f *model.Finding) string {
	if f.Triage == nil {
		return "P4"
	}
	return f.Triage.Priority
}

// CompareKeys orders two sort keys, larger first.
func CompareKeys(a, b [6]float64) int {
	for n := range a {
		if a[n] != b[n] {
			if a[n] > b[n] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// OrderLess sorts the most urgent findings first without inventing a score.
func OrderLess(a, b *model.Finding) bool {
	if ra, rb := PriorityRank(priorityOf(a)), PriorityRank(priorityOf(b)); ra != rb {
		return ra < rb
	}
	return CompareKeys(SortKey(a), SortKey(b)) < 0
}
