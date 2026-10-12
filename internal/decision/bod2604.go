package decision

// CISA BOD 26-04 response-policy evaluation, separate from the SSVC
// Deployer. The Deployer answers "how urgently should this organization
// deploy?"; BOD 26-04 answers "what remediation timeline does the directive
// assign?" with the published CERT/CC model cisa:DT_BOD2604:1.0.0, whose
// inputs are not the Deployer inputs:
//
//	In KEV (cisa:KEV:1.0.0)            vulnerability
//	Publicly Exposed (cisa:PE:1.0.0)   asset state -- not SSVC System Exposure
//	Automatable (ssvc:A:2.0.0)         vulnerability -- same point the Deployer uses
//	Technical Impact (ssvc:TI:1.0.0)   vulnerability -- not Human Impact
//
// This never changes the Deployer result. Input rules follow CISA's
// implementation guidance (retrieved 2026-10-11): a failed KEV lookup never
// becomes "No"; CISA's Automatable=No / Technical Impact=Total default
// applies only when both are unpublished after a completed Vulnrichment
// lookup and the CVE is confirmed not in KEV; Publicly Exposed is an
// explicit answer, and only positive exposure evidence sets it. Unresolved
// inputs produce every candidate outcome and a labelled provisional one.

import (
	"fmt"
	"sort"
	"strings"

	"github.com/d01ki/PatchTriage-go/internal/model"
)

const (
	PolicyID     = "cisa:DT_BOD2604:1.0.0"
	OutcomeGroup = "cisa:BOD2604:1.0.0"
)

// Sources records where the policy implementation comes from.
var Sources = map[string]map[string]string{
	"directive": {
		"title":     "BOD 26-04: Prioritizing Security Updates Based on Risk",
		"url":       "https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk",
		"issued":    "2026-06-10",
		"retrieved": "2026-10-11",
	},
	"implementation_guidance": {
		"title":     "BOD 26-04 Implementation Guidance",
		"url":       "https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk",
		"retrieved": "2026-10-11",
	},
	"decision_model": {
		"title":     "CERT/CC SSVC: CISA BOD 26-04 decision table",
		"url":       "https://certcc.github.io/SSVC/howto/cisa_response/",
		"data":      "https://github.com/CERTCC/SSVC/blob/main/data/csv/cisa/cisa_bod_26_04_1_0_0.csv",
		"retrieved": "2026-10-11",
	},
}

var applicabilityNotes = map[string]string{
	"unknown":        "Applicability not recorded; BOD 26-04 is shown for reference only.",
	"not_applicable": "BOD 26-04 does not apply to this target; shown for reference only.",
	"required":       "Federal civilian executive branch system: BOD 26-04 is a binding directive.",
	"voluntary":      "Organization voluntarily adopts BOD 26-04 timelines; not a legal obligation.",
}

func applied(applicability string) bool {
	return applicability == "required" || applicability == "voluntary"
}

// Outcome is one cisa:BOD2604:1.0.0 outcome. Days is a calendar-day
// maximum; FSU deliberately has none.
type Outcome struct {
	Label, Definition string
	Days              *int
	Obligations       []string
}

func days(n int) *int { return &n }

var Outcomes = map[string]Outcome{
	"FSU": {Label: "Fix on system upgrade", Definition: "Remediate the next time the asset receives a scheduled " +
		"major upgrade or rebuild, unless conditions change.", Obligations: []string{"remediate_at_next_major_upgrade"}},
	"60D": {Label: "60 days", Days: days(60), Definition: "Remediate within 60 calendar days.", Obligations: []string{"remediate"}},
	"14D": {Label: "14 days", Days: days(14), Definition: "Remediate within 14 calendar days.", Obligations: []string{"remediate"}},
	"3D":  {Label: "3 days", Days: days(3), Definition: "Remediate within 3 calendar days.", Obligations: []string{"remediate"}},
	"3DF": {Label: "3 days & forensic triage", Days: days(3), Definition: "Remediate or mitigate within 3 calendar days and carry " +
		"out a forensic triage of the asset to assess whether it is compromised.", Obligations: []string{"remediate", "forensic_triage"}},
}

var urgency = map[string]int{"FSU": 0, "60D": 1, "14D": 2, "3D": 3, "3DF": 4}

// ObligationLabels describes each obligation for reports.
var ObligationLabels = map[string]string{
	"remediate":                       "Remediate (patch, decommission, or otherwise eliminate)",
	"remediate_at_next_major_upgrade": "Remediate at the next scheduled major upgrade or rebuild",
	"forensic_triage":                 "Perform forensic triage per CISA's Forensic Triage Guidance",
}

// DeadlineAnchor explains why no absolute due date is computed.
const DeadlineAnchor = "Calendar days from the earlier of: CISA adding the CVE to KEV, or the " +
	"agency identifying it on the asset and updating the CDM dashboards " +
	"(BOD 23-01). Timelines are maximums and change when inputs change."

// bodTable is cisa:DT_BOD2604:1.0.0 keyed (In KEV, Publicly Exposed,
// Automatable, Technical Impact); all 16 rows are explicit.
var bodTable = map[[4]string]string{
	{"no", "no", "no", "partial"}:    "FSU",
	{"yes", "no", "no", "partial"}:   "14D",
	{"no", "yes", "no", "partial"}:   "60D",
	{"no", "no", "yes", "partial"}:   "60D",
	{"no", "no", "no", "total"}:      "FSU",
	{"yes", "yes", "no", "partial"}:  "14D",
	{"yes", "no", "yes", "partial"}:  "14D",
	{"no", "yes", "yes", "partial"}:  "14D",
	{"yes", "no", "no", "total"}:     "14D",
	{"no", "yes", "no", "total"}:     "14D",
	{"no", "no", "yes", "total"}:     "60D",
	{"yes", "yes", "yes", "partial"}: "3D",
	{"yes", "yes", "no", "total"}:    "3DF",
	{"yes", "no", "yes", "total"}:    "3DF",
	{"no", "yes", "yes", "total"}:    "3D",
	{"yes", "yes", "yes", "total"}:   "3DF",
}

var bodDomains = map[string][]string{
	"in_kev": {"no", "yes"}, "publicly_exposed": {"no", "yes"},
	"automatable": {"no", "yes"}, "technical_impact": {"partial", "total"},
}

var pointIDs = map[string]string{
	"in_kev": "cisa:KEV:1.0.0", "publicly_exposed": "cisa:PE:1.0.0",
	"automatable": "ssvc:A:2.0.0", "technical_impact": "ssvc:TI:1.0.0",
}

// BODOutcome looks up one fully specified row.
func BODOutcome(inKEV, publiclyExposed, automatable, technicalImpact string) string {
	return bodTable[[4]string{inKEV, publiclyExposed, automatable, technicalImpact}]
}

func input(name, value, source, basis string, defaulted bool) model.BODInput {
	return model.BODInput{Point: pointIDs[name], Value: value, Source: source, Basis: basis,
		Defaulted: defaulted, Resolved: value != "unknown"}
}

func inKEVInput(f *model.Finding) model.BODInput {
	status := f.Enrichment.RetrievalStatus["kev"]
	if f.Enrichment.InCISAKEV || status == "listed" || status == "listed_stale" {
		return input("in_kev", "yes", "CISA KEV", "CVE is listed in the CISA KEV catalog", false)
	}
	if status == "not_listed" {
		return input("in_kev", "no", "CISA KEV", "Completed KEV lookup did not list this CVE", false)
	}
	reason, ok := map[string]string{
		"failed":         "KEV lookup failed; non-membership is not established",
		"unknown_stale":  "Only a stale KEV catalog was available; a miss there does not establish non-membership",
		"not_applicable": "Identifier is not a CVE, so KEV membership cannot be looked up",
	}[status]
	if !ok {
		reason = "No completed KEV lookup is recorded"
	}
	return input("in_kev", "unknown", "unresolved", reason, false)
}

func publiclyExposedInput(a model.Asset) model.BODInput {
	if a.PubliclyExposed == "yes" || a.PubliclyExposed == "no" {
		return input("publicly_exposed", a.PubliclyExposed, "operator-confirmed", "Publicly Exposed answered for this target", false)
	}
	if a.InternetExposed != nil && *a.InternetExposed {
		return input("publicly_exposed", "yes", "internet exposure evidence",
			"Target is marked internet exposed; CISA sets Publicly Exposed to Yes when any method identifies exposure", false)
	}
	return input("publicly_exposed", "unknown", "unresolved",
		"Publicly Exposed is not recorded. SSVC System Exposure is a different decision point and is not used. "+
			"CISA's best-effort fallback needs routable-IP and asset-type tags PatchTriage does not hold", false)
}

func vulnrichmentCompleted(f *model.Finding) bool {
	status := f.Enrichment.RetrievalStatus["vulnrichment"]
	return status == "found" || status == "not_found"
}

func publishedAutomatable(f *model.Finding) *model.BODInput {
	if explicit := f.SSVCInputs["automatable"]; explicit == "yes" || explicit == "no" {
		in := input("automatable", explicit, "analyst-confirmed", "Automatable confirmed by an analyst for this CVE", false)
		return &in
	}
	if published := lowerPtr(f.Enrichment.SSVCAutomatable); published == "yes" || published == "no" {
		in := input("automatable", published, "CISA Vulnrichment", "CISA Vulnrichment publishes Automatable", false)
		return &in
	}
	for _, part := range strings.Split(strings.ToUpper(f.Enrichment.NVDCVSSVector), "/") {
		if part == "AU:Y" || part == "AU:N" {
			value := "no"
			if part == "AU:Y" {
				value = "yes"
			}
			in := input("automatable", value, "CVSS v4 Automatable", "CVSS v4 vector contains "+part, false)
			return &in
		}
	}
	return nil
}

func publishedTechnicalImpact(f *model.Finding) *model.BODInput {
	if published := lowerPtr(f.Enrichment.SSVCTechnicalImpact); published == "partial" || published == "total" {
		in := input("technical_impact", published, "CISA Vulnrichment", "CISA Vulnrichment publishes Technical Impact", false)
		return &in
	}
	return nil
}

func vulnerabilityPoints(f *model.Finding, inKEV model.BODInput) (model.BODInput, model.BODInput) {
	automatable, technical := publishedAutomatable(f), publishedTechnicalImpact(f)
	if automatable != nil && technical != nil {
		return *automatable, *technical
	}
	if automatable == nil && technical == nil && inKEV.Value == "no" && vulnrichmentCompleted(f) {
		basis := "Neither value is published and the CVE is not in KEV; CISA's implementation guidance " +
			"applies this default until metadata is published"
		return input("automatable", "no", "CISA guidance default", basis, true),
			input("technical_impact", "total", "CISA guidance default", basis, true)
	}
	var gap string
	switch {
	case inKEV.Value == "yes":
		gap = "CISA states it publishes Vulnrichment data for every KEV CVE; awaiting enrichment"
	case !vulnrichmentCompleted(f):
		gap = "Vulnrichment lookup did not complete"
	case inKEV.Value == "unknown":
		gap = "CISA's default applies only to CVEs confirmed not in KEV, and KEV membership is unresolved"
	default:
		gap = "Only one of Automatable / Technical Impact is published; CISA's default covers the case where both are missing"
	}
	if automatable == nil {
		in := input("automatable", "unknown", "unresolved", gap, false)
		automatable = &in
	}
	if technical == nil {
		in := input("technical_impact", "unknown", "unresolved", gap, false)
		technical = &in
	}
	return *automatable, *technical
}

func titleWords(name string) string {
	words := strings.Fields(strings.ReplaceAll(name, "_", " "))
	for n, w := range words {
		words[n] = strings.ToUpper(w[:1]) + strings.ToLower(w[1:])
	}
	return strings.Join(words, " ")
}

// EvaluateBOD returns the BOD 26-04 policy result for one finding.
func EvaluateBOD(f *model.Finding) model.BODResult {
	applicability := f.Asset.BOD2604Applicability
	if applicability == "" {
		applicability = "unknown"
	}
	note, ok := applicabilityNotes[applicability]
	if !ok {
		note = applicabilityNotes["unknown"]
	}
	inputs := model.BODInputs{InKEV: inKEVInput(f), PubliclyExposed: publiclyExposedInput(f.Asset)}
	inputs.Automatable, inputs.TechnicalImpact = vulnerabilityPoints(f, inputs.InKEV)

	unresolved := []string{}
	choices := make([][]string, len(model.BODInputNames))
	for n, name := range model.BODInputNames {
		in := inputs.Get(name)
		if in.Resolved {
			choices[n] = []string{in.Value}
		} else {
			unresolved = append(unresolved, name)
			choices[n] = bodDomains[name]
		}
	}
	seen := map[string]bool{}
	var candidates []string
	for _, k := range choices[0] {
		for _, p := range choices[1] {
			for _, a := range choices[2] {
				for _, ti := range choices[3] {
					if outcome := BODOutcome(k, p, a, ti); !seen[outcome] {
						seen[outcome] = true
						candidates = append(candidates, outcome)
					}
				}
			}
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return urgency[candidates[i]] > urgency[candidates[j]] })

	result := model.BODResult{Policy: PolicyID, OutcomeGroup: OutcomeGroup, Applicability: applicability,
		ApplicabilityNote: note, Applied: applied(applicability), Inputs: inputs, UnresolvedInputs: unresolved,
		CandidateOutcomes: candidates, DeadlineAnchor: DeadlineAnchor}
	shown := candidates[0]
	if len(candidates) == 1 {
		result.Status = "resolved"
		result.Outcome, result.OutcomeLabel = &shown, strp(Outcomes[shown].Label)
	} else {
		result.Status = "unresolved"
		result.ProvisionalOutcome, result.ProvisionalLabel = &shown, strp(Outcomes[shown].Label)
	}
	result.DeadlineDays = Outcomes[shown].Days
	result.Definition = Outcomes[shown].Definition
	result.Obligations = append([]string{}, Outcomes[shown].Obligations...)
	if f.Enrichment.KEVDateAdded != nil {
		result.KEVDateAdded = *f.Enrichment.KEVDateAdded
	}
	if f.Enrichment.KEVDueDate != nil {
		result.KEVDueDate = *f.Enrichment.KEVDueDate
	}
	if result.Status == "unresolved" {
		var names, labels []string
		for _, name := range unresolved {
			names = append(names, strings.ReplaceAll(name, "_", " "))
		}
		for _, c := range candidates {
			labels = append(labels, Outcomes[c].Label)
		}
		result.Rationale = "BOD 26-04 outcome unresolved: " + strings.Join(names, ", ") +
			" not established. Candidate outcomes: " + strings.Join(labels, ", ") +
			". Provisional (most urgent): " + Outcomes[shown].Label + "."
	} else {
		var path []string
		for _, name := range model.BODInputNames {
			value := "any"
			if in := inputs.Get(name); in.Resolved {
				value = in.Value
			}
			path = append(path, titleWords(name)+":"+value)
		}
		result.Rationale = fmt.Sprintf("%s path %s => %s.", PolicyID, strings.Join(path, " / "), Outcomes[shown].Label)
	}
	return result
}

func strp(s string) *string { return &s }

func daysText(v *int) string {
	if v == nil {
		return "None"
	}
	return fmt.Sprint(*v)
}

// ResolveEffective combines the SSVC workflow target and the BOD result by
// explicit, named rules:
//
//	ssvc_only                  BOD not applied; the SSVC workflow target governs.
//	bod_unresolved_provisional BOD applied, inputs missing; the earlier of the workflow
//	                           target and the provisional BOD timeline, needing confirmation.
//	bod_fix_on_upgrade         no numeric BOD deadline; the workflow target sets the
//	                           working deadline and the upgrade obligation remains.
//	bod_maximum                the BOD timeline is not later than the workflow target.
//	workflow_target_stricter   the organization's own target is earlier and satisfies it.
//
// Every applicable obligation (e.g. forensic triage) is preserved even when
// a shorter numeric deadline comes from another source.
func ResolveEffective(ssvc *model.SSVCAssessment, p model.BODResult) model.Effective {
	var ssvcDays *int
	label := ""
	if ssvc != nil {
		ssvcDays, label = days(ssvc.SuggestedDeadlineDays), ssvc.DecisionLabel
	}
	key := ""
	if p.Outcome != nil {
		key = *p.Outcome
	} else if p.ProvisionalOutcome != nil {
		key = *p.ProvisionalOutcome
	}
	e := model.Effective{SSVCOutcome: label, SSVCWorkflowDays: ssvcDays, BODStatus: p.Status, Obligations: []string{}}
	if key != "" {
		e.BODOutcome = strp(key)
	}
	if !p.Applied {
		e.Rule, e.DeadlineDays, e.DeadlineSource = "ssvc_only", ssvcDays, "SSVC workflow target"
		e.Explanation = fmt.Sprintf("SSVC %s: PatchTriage workflow target %s days. BOD 26-04 is not applied to this "+
			"target (%s); its result is shown for reference only.", label, daysText(ssvcDays), p.Applicability)
		e.Obligations = []string{"remediate"}
		return e
	}
	outcome := Outcomes[key]
	obligations := append([]string{}, outcome.Obligations...)
	if !contains(obligations, "remediate") && ssvcDays != nil {
		obligations = append([]string{"remediate"}, obligations...)
	}
	e.Obligations = obligations
	switch {
	case p.Status != "resolved":
		deadline := ssvcDays
		if outcome.Days != nil && (deadline == nil || *outcome.Days < *deadline) {
			deadline = outcome.Days
		}
		e.Rule, e.DeadlineDays, e.DeadlineSource, e.RequiresConfirmation = "bod_unresolved_provisional", deadline, "provisional", true
		e.Explanation = fmt.Sprintf("Provisional: BOD 26-04 inputs %s are unresolved. Using the most urgent candidate (%s) "+
			"against the SSVC workflow target (%s days) until they are confirmed.",
			strings.Join(p.UnresolvedInputs, ", "), outcome.Label, daysText(ssvcDays))
	case outcome.Days == nil:
		e.Rule, e.DeadlineDays, e.DeadlineSource = "bod_fix_on_upgrade", ssvcDays, "SSVC workflow target"
		e.Explanation = fmt.Sprintf("BOD 26-04 assigns %s: remediate at the next scheduled major upgrade or rebuild. "+
			"The SSVC %s workflow target (%s days) sets the working deadline; the upgrade obligation still applies.",
			outcome.Label, label, daysText(ssvcDays))
	case ssvcDays == nil || *outcome.Days <= *ssvcDays:
		e.Rule, e.DeadlineDays, e.DeadlineSource = "bod_maximum", outcome.Days, "BOD 26-04 maximum"
		e.Explanation = fmt.Sprintf("BOD 26-04 assigns %s, a calendar-day maximum not later than the SSVC %s "+
			"workflow target (%s days).", outcome.Label, label, daysText(ssvcDays))
	default:
		e.Rule, e.DeadlineDays, e.DeadlineSource = "workflow_target_stricter", ssvcDays, "SSVC workflow target"
		e.Explanation = fmt.Sprintf("The SSVC %s workflow target (%s days) is earlier than the BOD 26-04 maximum (%s) "+
			"and satisfies it.", label, daysText(ssvcDays), outcome.Label)
	}
	return e
}

// ApplyPolicy attaches the BOD result and effective action to each triaged
// finding. The SSVC record and the triage priority are left untouched; only
// the deterministic SSVC record is consulted, never free-form text.
func ApplyPolicy(findings []*model.Finding) {
	for _, f := range findings {
		if f.Triage == nil {
			continue
		}
		policy := EvaluateBOD(f)
		effective := ResolveEffective(f.Triage.SSVC, policy)
		f.Triage.BOD2604, f.Triage.Effective = &policy, &effective
	}
}

// ActionPolicy is the policy view of one package action.
type ActionPolicy struct {
	BOD2604               map[string]any
	EffectiveDeadlineDays *int
	EffectiveRule         string
	Obligations           []string
}

// PolicyForAction aggregates the policy view of an action's findings: the
// most urgent BOD outcome, every obligation of every finding, and the
// earliest effective deadline with the rule that set it.
func PolicyForAction(group []*model.Finding) (ActionPolicy, bool) {
	type pair struct {
		policy    *model.BODResult
		effective *model.Effective
	}
	var pairs []pair
	for _, f := range group {
		if f.Triage != nil && f.Triage.BOD2604 != nil && f.Triage.Effective != nil {
			pairs = append(pairs, pair{f.Triage.BOD2604, f.Triage.Effective})
		}
	}
	if len(pairs) == 0 {
		return ActionPolicy{}, false
	}
	unresolved, top, forensic := 0, "", false
	obligations := []string{}
	var governing *model.Effective
	for _, pr := range pairs {
		if pr.policy.Status != "resolved" {
			unresolved++
		}
		key := ""
		if pr.policy.Outcome != nil {
			key = *pr.policy.Outcome
		} else if pr.policy.ProvisionalOutcome != nil {
			key = *pr.policy.ProvisionalOutcome
		}
		if top == "" || urgency[key] > urgency[top] {
			top = key
		}
		forensic = forensic || contains(Outcomes[key].Obligations, "forensic_triage")
		for _, item := range pr.effective.Obligations {
			if !contains(obligations, item) {
				obligations = append(obligations, item)
			}
		}
		if pr.effective.DeadlineDays != nil && (governing == nil || *pr.effective.DeadlineDays < *governing.DeadlineDays) {
			governing = pr.effective
		}
	}
	if governing == nil {
		governing = pairs[0].effective
	}
	status := "resolved"
	if unresolved > 0 {
		status = "unresolved"
	}
	first := pairs[0].policy
	return ActionPolicy{
		BOD2604: map[string]any{"policy": PolicyID, "outcome": top, "label": Outcomes[top].Label, "status": status,
			"unresolved_findings": unresolved, "applicability": first.Applicability, "applied": first.Applied,
			"forensic_triage": forensic},
		EffectiveDeadlineDays: governing.DeadlineDays, EffectiveRule: governing.Rule, Obligations: obligations,
	}, true
}

// SummarizePolicy gives the counts used by the GUI, CLI and report. It is
// never a compliance verdict.
func SummarizePolicy(findings []*model.Finding) map[string]any {
	outcomes := map[string]int{}
	for key := range Outcomes {
		outcomes[key] = 0
	}
	evaluated, resolved, forensic, anyApplied := 0, 0, 0, false
	applicability := map[string]bool{}
	for _, f := range findings {
		if f.Triage == nil || f.Triage.BOD2604 == nil {
			continue
		}
		r := f.Triage.BOD2604
		evaluated++
		if r.Status == "resolved" {
			resolved++
			outcomes[*r.Outcome]++
		}
		if contains(r.Obligations, "forensic_triage") {
			forensic++
		}
		applicability[r.Applicability] = true
		anyApplied = anyApplied || r.Applied
	}
	var kinds []string
	for k := range applicability {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	if kinds == nil {
		kinds = []string{}
	}
	return map[string]any{
		"policy": PolicyID, "evaluated": evaluated, "resolved": resolved, "unresolved": evaluated - resolved,
		"outcomes": outcomes, "forensic_triage": forensic, "applicability": kinds,
		"applied": anyApplied, "sources": Sources,
	}
}
