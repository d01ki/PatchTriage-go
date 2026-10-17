package web

// Run the assessment for one registered target and summarize it for the
// GUI. The summary keys match the Python implementation so the single-page
// console works unchanged.

import (
	"context"
	"errors"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/d01ki/PatchTriage-go/data"
	"github.com/d01ki/PatchTriage-go/internal/decision"
	"github.com/d01ki/PatchTriage-go/internal/enrich"
	"github.com/d01ki/PatchTriage-go/internal/ingest"
	"github.com/d01ki/PatchTriage-go/internal/model"
	"github.com/d01ki/PatchTriage-go/internal/pipeline"
	"github.com/d01ki/PatchTriage-go/internal/report"

	"github.com/d01ki/PatchTriage-go/internal/repository"

	"slices"
)

func envLimit(name string, fallback int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil {
		return max(1, v)
	}
	return fallback
}

var (
	maxWebSSVCInputs  = envLimit("PATCHTRIAGE_MAX_WEB_SSVC_INPUTS", 250)
	maxSummaryActions = envLimit("PATCHTRIAGE_MAX_SUMMARY_ACTIONS", 25)
	maxDecisionPaths  = envLimit("PATCHTRIAGE_MAX_DECISION_PATHS", 100)
	maxOverviewRows   = envLimit("PATCHTRIAGE_MAX_OVERVIEW_ROWS", 5000)
)

var sourceNames = map[string]string{"msrc": "Microsoft", "rhsa": "Red Hat", "usn": "Ubuntu",
	"debian": "Debian", "ghsa": "GitHub", "exploitdb": "Exploit-DB"}

// Runner assesses targets with the configured live providers.
type Runner struct {
	Store  *Store
	Enrich enrich.Options    // live provider settings (the demo uses bundled data)
	OSV    *ingest.OSVClient // SBOM resolution
}

// demoUpdates is the demo target's context, as POST /api/demo sets it.
var demoUpdates = map[string]any{
	"criticality": "critical", "internet_exposed": true, "reachable": true, "runtime_observed": true,
	"system_exposure": "open", "mission_impact": "mef_failure", "safety_impact": "critical",
	"context_sources": []any{"OpenTelemetry", "Falco"}, "ssvc_overrides": map[string]any{},
}

// CreateDemoTarget returns the workspace's demo target (creating it when
// absent) with the bundled Trivy fixture attached.
func CreateDemoTarget(s *Store, ws string, maxTargets int, maxSourceBytes int64) (Target, bool, error) {
	targets, err := s.Load(ws)
	if err != nil {
		return nil, false, err
	}
	var target Target
	for _, t := range targets {
		if t["demo"] == true {
			target = t
			break
		}
	}
	created := target == nil
	if created {
		fields := map[string]any{"name": "Demo", "demo": true}
		for k, v := range demoUpdates {
			fields[k] = v
		}
		if target, err = s.Add(ws, fields, maxTargets); err != nil {
			return nil, false, err
		}
	}
	fixture, err := data.ReadFile("fixtures/trivy_sample.json")
	if err != nil {
		return nil, false, err
	}
	id := target["id"].(string)
	err = s.SaveSource(ws, id, string(fixture), Source{Format: "trivy", Filename: "trivy_sample.json", Kind: "demo",
		Provenance: map[string]any{"provider": "bundled-demo", "offline": true,
			"coverage": map[string]any{"status": "complete", "reason": "Bundled scanner fixture"}},
		Updates: demoUpdates}, maxSourceBytes)
	if err != nil {
		if created {
			_, _ = s.Delete(ws, id)
		}
		return nil, false, err
	}
	target, err = s.Get(ws, id)
	return target, created, err
}

func evidenceLinks(f *model.Finding) []map[string]any {
	links := []map[string]any{}
	if strings.HasPrefix(f.VulnID, "CVE-") {
		links = append(links, map[string]any{"source": "NVD", "label": f.VulnID,
			"url": "https://nvd.nist.gov/vuln/detail/" + f.VulnID})
		if f.Enrichment.InCISAKEV {
			links = append(links, map[string]any{"source": "CISA KEV", "label": "Known exploited",
				"url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=" + f.VulnID})
		}
	}
	// Grouped per source so one prolific feed cannot hide another; public
	// exploit evidence first because it moves SSVC Exploitation.
	bySource := map[string][]model.VendorAdvisory{}
	for _, a := range f.Enrichment.VendorAdvisories {
		bySource[a.Source] = append(bySource[a.Source], a)
	}
	for _, source := range []string{"exploitdb", "msrc", "rhsa", "debian", "usn", "ghsa"} {
		records := bySource[source]
		for i, a := range records[:min(2, len(records))] {
			link, more := "", 0
			if strings.HasPrefix(a.URL, "https://") {
				link = a.URL
			}
			if i == 1 && len(records) > 2 {
				more = len(records) - 2
			}
			name, ok := sourceNames[source]
			if !ok {
				name = source
			}
			links = append(links, map[string]any{"source": name, "label": a.AdvisoryID, "url": link, "more": more})
		}
	}
	return links
}

// DecisionPath is a finding's Deployer path plus the Human Impact branches
// below it, for the GUI decision-tree view.
func DecisionPath(f *model.Finding) map[string]any {
	if f.Triage == nil || f.Triage.SSVC == nil {
		return nil
	}
	s := f.Triage.SSVC
	points := map[string]any{}
	for key, p := range map[string]model.DecisionPoint{"exploitation": s.Exploitation, "system_exposure": s.SystemExposure,
		"automatable": s.Automatable, "mission_impact": s.MissionImpact, "safety_impact": s.SafetyImpact, "human_impact": s.HumanImpact} {
		points[key] = map[string]any{"value": p.Value, "label": p.Label, "source": p.Source,
			"confidence": p.Confidence, "needs_confirmation": p.NeedsConfirmation}
	}
	var policy any
	if p := f.Triage.BOD2604; p != nil {
		label := ""
		if p.OutcomeLabel != nil {
			label = *p.OutcomeLabel
		} else if p.ProvisionalLabel != nil {
			label = "provisional " + *p.ProvisionalLabel
		}
		policy = map[string]any{"label": label, "status": p.Status, "applied": p.Applied}
	}
	return map[string]any{
		"finding_key": f.Key, "vuln_id": f.VulnID, "package": f.Package.Name, "version": f.Package.Version,
		"version_source": f.Package.VersionSource, "fixed_version": f.Package.FixedVersion, "asset": f.Asset.Identifier,
		"model": s.Model, "decision": s.Decision, "decision_label": s.DecisionLabel, "points": points,
		"branches": decision.HumanImpactBranches(s.Exploitation.Value, s.SystemExposure.Value, s.Automatable.Value),
		"bod2604":  policy, "evidence": evidenceLinks(f),
	}
}

// OverviewRow is the compact per-finding record behind the GUI overview:
// the SSVC decision point values only, so every finding fits in the summary.
// path is the index of the finding's full entry in decision_paths, when the
// summary carries one.
func OverviewRow(f *model.Finding, path int) map[string]any {
	if f.Triage == nil || f.Triage.SSVC == nil {
		return nil
	}
	s := f.Triage.SSVC
	assumed := []string{}
	for _, p := range []struct {
		key   string
		point model.DecisionPoint
	}{{"exploitation", s.Exploitation}, {"system_exposure", s.SystemExposure}, {"automatable", s.Automatable},
		{"human_impact", s.HumanImpact}} {
		if p.point.NeedsConfirmation {
			assumed = append(assumed, p.key)
		}
	}
	row := map[string]any{
		"finding_key": f.Key, "vuln_id": f.VulnID, "package": f.Package.Name, "version": f.Package.Version,
		"asset": f.Asset.Identifier, "decision": s.Decision, "decision_label": s.DecisionLabel,
		"exploitation": s.Exploitation.Value, "system_exposure": s.SystemExposure.Value,
		"automatable": s.Automatable.Value, "human_impact": s.HumanImpact.Value, "assumed": assumed,
		"kev": f.Enrichment.InCISAKEV,
	}
	if path >= 0 {
		row["path"] = path
	}
	return row
}

func cvssOf(f *model.Finding) *float64 {
	if f.Enrichment.NVDCVSSScore != nil && *f.Enrichment.NVDCVSSScore != 0 {
		return f.Enrichment.NVDCVSSScore
	}
	return f.CVSSScore
}

func priorityOf(f *model.Finding) string {
	if f.Triage == nil {
		return "P4"
	}
	return f.Triage.Priority
}

func explanation(findings []*model.Finding, top pipeline.Action) map[string]any {
	var candidates, pool []*model.Finding
	keys := map[string]bool{}
	for _, k := range top.FindingKeys {
		keys[k] = true
	}
	for _, f := range findings {
		if keys[f.Key] {
			candidates = append(candidates, f)
		}
	}
	for _, f := range candidates {
		if priorityOf(f) == top.TopPriority {
			pool = append(pool, f)
		}
	}
	if len(pool) == 0 {
		pool = candidates
	}
	if len(pool) == 0 {
		return nil
	}
	f := pool[0]
	for _, other := range pool[1:] {
		if decision.OrderLess(other, f) {
			f = other
		}
	}
	info := pipeline.PriorityDefinition(priorityOf(f))
	e := f.Enrichment
	confidence, confirmation := "low", []string{}
	var ssvc any = map[string]any{}
	if f.Triage != nil && f.Triage.SSVC != nil {
		ssvc, confidence, confirmation = f.Triage.SSVC, f.Triage.SSVC.Confidence, f.Triage.SSVC.NeedsConfirmation
	}
	advisories := e.VendorAdvisories[:min(5, len(e.VendorAdvisories))]
	if advisories == nil {
		advisories = []model.VendorAdvisory{}
	}
	return map[string]any{
		"vuln_id": f.VulnID, "package": f.Package.Name, "outcome_label": info["ssvc_outcome"],
		"outcome_description": info["description"], "basis": pipeline.PriorityBasis(f),
		"checks": pipeline.PriorityEvidence(f), "rationale": f.Triage.Rationale, "ssvc": ssvc,
		"bod2604": f.Triage.BOD2604, "effective": f.Triage.Effective, "confidence": confidence,
		"needs_confirmation": confirmation, "cvss": cvssOf(f), "epss": e.EPSSScore, "kev": e.InCISAKEV,
		"retrieval_status": e.RetrievalStatus, "retrieval_errors": nonNil(e.RetrievalErrors),
		"ransomware": e.KEVRansomware, "has_fix": f.Package.FixedVersion != "", "advisories": advisories,
	}
}

func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func comparison(rows []pipeline.EvalRow, total int) map[string]any {
	if len(rows) == 0 {
		return nil
	}
	r := rows[0]
	return map[string]any{
		"k": r.K, "kev_total": r.KEVTotal,
		"kev": map[string]any{"cvss": r.KEVBaseline, "epss": r.KEVEPSS, "kev": r.KEVKEV, "ssvc": r.KEVSSVC, "patchtriage": r.KEVPatchTriage},
		"epss_mass": map[string]any{"cvss": r.EPSSBaseline, "epss": r.EPSSEPSS, "kev": r.EPSSKEV, "ssvc": r.EPSSSSVC,
			"patchtriage": r.EPSSPatchTriage},
		"urgent":  map[string]any{"total": r.UrgentTotal, "cvss": r.UrgentCVSS, "epss": r.UrgentEPSS, "kev": r.UrgentKEV, "ssvc": r.UrgentSSVC},
		"outcome": pipeline.EvaluationOutcome(r, total),
	}
}

func sortedSet(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range values {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

func copyMap(m map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		out[k] = v
	}
	return out
}

// Run assesses one target: ingest -> enrich -> triage -> plan -> report,
// publishing the summary and report only if the target did not change.
// Run assesses one target with backend ("rules", "ai", "claude" or
// "cascade"; "" is rules).
func (r *Runner) Run(ctx context.Context, ws string, target Target, backend string) (map[string]any, error) {
	started := time.Now()
	id := strOf(target["id"])
	revision, sha := intOf(target["input_revision"]), strOf(target["source_sha256"])
	source := strOf(target["source_file"])
	if source == "" {
		return nil, errors.New("no scan or SBOM attached to this target")
	}
	override := pipeline.AssetFromTarget(target)
	provenance := map[string]any{}
	if p, ok := target["source_provenance"].(map[string]any); ok {
		provenance = copyMap(p)
	}
	providerStatus := strOf(provenance["coverage_status"])
	if kind := strOf(target["source_kind"]); providerStatus == "" && (kind == "" || kind == "upload") {
		providerStatus = "provider_reported"
	}
	declared, _ := provenance["coverage"].(map[string]any)
	overrides := map[string]map[string]string{}
	if raw, ok := target["ssvc_overrides"].(map[string]any); ok {
		for key, values := range raw {
			if m, ok := values.(map[string]any); ok {
				overrides[key] = map[string]string{}
				for k, v := range m {
					overrides[key][k] = strOf(v)
				}
			}
		}
	}
	options := pipeline.Options{Asset: &override, SSVCOverrides: overrides, DeclaredCoverage: copyMap(declared),
		ProviderStatus: providerStatus, Enrich: r.Enrich, OSV: r.OSV,
		Triage: pipeline.TriageOptions{Backend: backend, Jobs: 4}}
	if options.Enrich.GitHubToken == "" {
		options.Enrich.GitHubToken = os.Getenv("GITHUB_TOKEN")
		if options.Enrich.GitHubToken == "" {
			options.Enrich.GitHubToken = os.Getenv("GH_TOKEN")
		}
	}
	if target["demo"] == true {
		snapshot, err := enrich.DemoSnapshot()
		if err != nil {
			return nil, err
		}
		options.Snapshot = &snapshot
	}
	var staleErr error
	options.OnCoverage = func(c model.Coverage) {
		provenance["coverage"], provenance["coverage_status"] = c, c["status"]
		if err := r.Store.UpdateProvenanceIfCurrent(ws, id, provenance, revision, sha); err != nil {
			staleErr = err
		}
	}
	result, err := pipeline.Assess(ctx, []string{source}, options)
	if err == nil {
		err = staleErr
	}
	if err != nil {
		return nil, err
	}
	findings, actions := result.Findings, result.Actions
	var warnings []string
	if w, ok := provenance["warnings"].([]any); ok {
		for _, item := range w {
			warnings = append(warnings, strOf(item))
		}
	}
	html, err := report.RenderHTML(findings, actions, result.EvalRows, report.HTMLOptions{
		Title: "PatchTriage - " + strOf(target["name"]), Coverage: result.Coverage, CoverageWarnings: warnings})
	if err != nil {
		return nil, err
	}

	outcomes := map[string]int{"immediate": 0, "out_of_cycle": 0, "scheduled": 0, "defer": 0}
	kev := 0
	advisoryKeys := map[[2]string]bool{}
	var vendorSources, vendorErrors, enrichmentErrors, confirmation []string
	for _, f := range findings {
		key := "defer"
		if f.Triage != nil && f.Triage.SSVC != nil {
			if _, known := outcomes[f.Triage.SSVC.Decision]; known {
				key = f.Triage.SSVC.Decision
			}
			confirmation = append(confirmation, f.Triage.SSVC.NeedsConfirmation...)
		}
		outcomes[key]++
		if f.Enrichment.InCISAKEV {
			kev++
		}
		for _, a := range f.Enrichment.VendorAdvisories {
			advisoryKeys[[2]string{a.Source, a.AdvisoryID}] = true
		}
		vendorSources = append(vendorSources, f.Enrichment.VendorSourcesChecked...)
		vendorErrors = append(vendorErrors, f.Enrichment.VendorLookupErrors...)
		enrichmentErrors = append(enrichmentErrors, f.Enrichment.RetrievalErrors...)
	}

	ordered := append([]*model.Finding(nil), findings...)
	sort.SliceStable(ordered, func(i, j int) bool { return decision.OrderLess(ordered[i], ordered[j]) })
	inputs := []map[string]any{}
	reviewTotal := 0
	for _, f := range ordered {
		var exploitation, automatable any = map[string]any{}, map[string]any{}
		needsReview := false
		if f.Triage != nil && f.Triage.SSVC != nil {
			exploitation, automatable = f.Triage.SSVC.Exploitation, f.Triage.SSVC.Automatable
			needsReview = f.Triage.SSVC.Exploitation.NeedsConfirmation || f.Triage.SSVC.Automatable.NeedsConfirmation
		}
		if needsReview {
			reviewTotal++
		}
		if len(inputs) < maxWebSSVCInputs {
			inputs = append(inputs, map[string]any{"finding_key": f.Key, "vuln_id": f.VulnID, "package": f.Package.Name,
				"exploitation": exploitation, "automatable": automatable, "override": f.SSVCInputs, "needs_review": needsReview})
		}
	}
	paths := []map[string]any{}
	pathIndex := map[string]int{}
	for _, f := range ordered[:min(maxDecisionPaths, len(ordered))] {
		if p := DecisionPath(f); p != nil {
			pathIndex[f.Key] = len(paths)
			paths = append(paths, p)
		}
	}
	overview := []map[string]any{}
	for _, f := range ordered[:min(maxOverviewRows, len(ordered))] {
		index, ok := pathIndex[f.Key]
		if !ok {
			index = -1
		}
		if row := OverviewRow(f, index); row != nil {
			overview = append(overview, row)
		}
	}
	queue := []map[string]any{}
	for _, a := range actions[:min(maxSummaryActions, len(actions))] {
		queue = append(queue, map[string]any{
			"action_id": a.ActionID, "kind": a.Kind, "summary": a.Summary, "package": a.Package,
			"ecosystem": a.Ecosystem, "installed_version": a.InstalledVersion, "target_version": a.TargetVersion,
			"top_priority": a.TopPriority, "outcome_label": pipeline.PriorityDefinition(a.TopPriority)["ssvc_outcome"],
			"deadline_days": a.DeadlineDays, "kev_count": a.KEVCount, "cves": a.CVEs[:min(8, len(a.CVEs))],
			"finding_count": len(a.FindingKeys), "bod2604": a.BOD2604, "effective_deadline_days": a.EffectiveDeadlineDays,
			"effective_rule": a.EffectiveRule, "obligations": a.Obligations,
		})
	}

	coverage, _ := provenance["coverage"].(map[string]any)
	if coverage == nil {
		coverage = model.Coverage(result.Coverage)
	}
	status := strOf(coverage["status"])
	if status == "" {
		status = strOf(provenance["coverage_status"])
	}
	if status == "" {
		status = "complete"
		if f := strOf(target["source_format"]); f == "cyclonedx" || f == "spdx" {
			status = "unknown"
		}
	}
	incomplete := status != "complete"
	state := "no_plan"
	switch {
	case len(findings) == 0 && incomplete:
		state = "coverage_incomplete"
	case len(findings) == 0:
		state = "no_findings"
	case incomplete && len(actions) > 0:
		state = "assessed_incomplete"
	case len(actions) > 0:
		state = "assessed"
	}
	auditRate := 100.0
	if len(findings) > 0 {
		auditRate = pipelineRound(float64(result.Audit.Verified) / float64(len(findings)) * 100)
	}
	var top any = ""
	var topDays any
	topDecision := ""
	var explain any
	if len(actions) > 0 {
		top, topDays = actions[0].Summary, actions[0].DeadlineDays
		if e := explanation(findings, actions[0]); e != nil {
			explain = e
			if s, ok := e["ssvc"].(*model.SSVCAssessment); ok {
				topDecision = s.DecisionLabel
			}
		}
	}
	kind := strOf(target["source_kind"])
	if kind == "" {
		kind = "upload"
	}
	summary := map[string]any{
		"target_id": id, "name": target["name"], "url": strOf(target["url"]), "total": len(findings),
		"outcomes": outcomes, "kev": kev, "vendor_advisories": len(advisoryKeys), "vendor_sources": sortedSet(vendorSources),
		"vendor_errors": sortedSet(vendorErrors), "enrichment_errors": sortedSet(enrichmentErrors), "actions": len(actions),
		"decision_quality": pipeline.DecisionQuality(findings), "audit_verified": result.Audit.Verified,
		"audit_flagged": len(result.Audit.Flagged), "audit_rate": auditRate, "top_action": top,
		"top_deadline_days": topDays, "top_ssvc_decision": topDecision, "action_queue": queue,
		"action_queue_truncated": len(actions) > maxSummaryActions,
		"response_policy":        decision.SummarizePolicy(findings),
		"evaluated_context": map[string]any{"system_exposure": override.SystemExposure, "mission_impact": override.MissionImpact,
			"safety_impact": override.SafetyImpact, "publicly_exposed": override.PubliclyExposed,
			"bod2604_applicability": override.BOD2604Applicability, "context_sources": override.ContextSources},
		"result_state":   state,
		"result_message": pipeline.ResultMessage(len(findings), len(actions), incomplete, status, result.Coverage),
		"source": map[string]any{"kind": kind, "format": strOf(target["source_format"]), "name": strOf(target["source_name"]),
			"sha256": sha, "size": target["source_size"], "provenance": provenance, "coverage_status": status},
		"ssvc_confirmation_fields": sortedSet(confirmation), "ssvc_inputs": inputs, "decision_paths": paths,
		"decision_paths_truncated": len(ordered) > maxDecisionPaths, "ssvc_inputs_total": len(ordered),
		"overview": overview, "overview_truncated": len(ordered) > maxOverviewRows,
		"ssvc_inputs_review_total": reviewTotal, "ssvc_inputs_truncated": len(ordered) > len(inputs),
		"explanation": explain, "comparison": comparison(result.EvalRows, len(findings)), "demo": target["demo"] == true,
		"duration_ms": time.Since(started).Milliseconds(), "report_url": "/report/" + id,
	}
	if err := r.Store.SaveRunArtifacts(ws, id, summary, html, revision, sha); err != nil {
		return nil, err
	}
	return summary, nil
}

// pipelineRound rounds to one decimal like Python's round(x, 1).
func pipelineRound(x float64) float64 {
	v, _ := strconv.ParseFloat(strconv.FormatFloat(x, 'f', 1, 64), 64)
	return v
}

var priorityOrder = map[string]int{"P1": 0, "P2": 1, "P3": 2, "P4": 3}

// AggregateFleet merges stored per-target summaries into one rollup. It
// never re-decides anything, and unassessed targets stay visible. A non-nil
// ids limits the rollup to those targets.
func AggregateFleet(s *Store, ws string, ids []string) (map[string]any, error) {
	targets, err := s.Load(ws)
	if err != nil {
		return nil, err
	}
	if ids != nil {
		targets = slices.DeleteFunc(targets, func(t Target) bool { return !slices.Contains(ids, strOf(t["id"])) })
	}
	outcomes := map[string]int{"immediate": 0, "out_of_cycle": 0, "scheduled": 0, "defer": 0}
	queue := []map[string]any{}
	rows := []map[string]any{}
	findings, kev, assessed, truncatedTargets, incomplete := 0, 0, 0, 0, 0
	for _, t := range targets {
		id := strOf(t["id"])
		row := map[string]any{"target_id": id, "name": strOf(t["name"]), "url": strOf(t["url"]),
			"source_kind": strOf(t["source_kind"]), "assessed": false}
		summary := s.LoadSummary(ws, id)
		if summary == nil {
			row["result_state"] = "not_assessed"
			rows = append(rows, row)
			continue
		}
		assessed++
		findings += intOf(summary["total"])
		kev += intOf(summary["kev"])
		if o, ok := summary["outcomes"].(map[string]any); ok {
			for k := range outcomes {
				outcomes[k] += intOf(o[k])
			}
		}
		if summary["action_queue_truncated"] == true {
			truncatedTargets++
		}
		if entries, ok := summary["action_queue"].([]any); ok {
			for _, e := range entries {
				if entry, ok := e.(map[string]any); ok {
					entry = copyMap(entry)
					entry["target_id"], entry["target_name"] = id, strOf(t["name"])
					queue = append(queue, entry)
				}
			}
		}
		source, _ := summary["source"].(map[string]any)
		coverage := strOf(source["coverage_status"])
		if coverage != "complete" {
			incomplete++
		}
		row["assessed"] = true
		for k, v := range map[string]any{"result_state": summary["result_state"], "coverage_status": coverage,
			"total": summary["total"], "outcomes": summary["outcomes"], "kev": summary["kev"],
			"top_action": summary["top_action"], "report_url": summary["report_url"]} {
			row[k] = v
		}
		rows = append(rows, row)
	}
	rank := func(e map[string]any) int {
		if r, ok := priorityOrder[strOf(e["top_priority"])]; ok {
			return r
		}
		return 4
	}
	days := func(e map[string]any) int {
		if d := intOf(e["deadline_days"]); d != 0 {
			return d
		}
		return 90
	}
	sort.SliceStable(queue, func(i, j int) bool {
		a, b := queue[i], queue[j]
		switch {
		case rank(a) != rank(b):
			return rank(a) < rank(b)
		case days(a) != days(b):
			return days(a) < days(b)
		case intOf(a["kev_count"]) != intOf(b["kev_count"]):
			return intOf(a["kev_count"]) > intOf(b["kev_count"])
		case intOf(a["finding_count"]) != intOf(b["finding_count"]):
			return intOf(a["finding_count"]) > intOf(b["finding_count"])
		}
		return strOf(a["package"]) < strOf(b["package"])
	})
	const maxQueue = 50
	return map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339Nano), "targets_total": len(rows),
		"targets_assessed": assessed, "targets_unassessed": len(rows) - assessed, "findings_total": findings,
		"kev_total": kev, "outcomes": outcomes, "queue": queue[:min(maxQueue, len(queue))], "queue_total": len(queue),
		"queue_truncated": len(queue) > maxQueue || truncatedTargets > 0, "targets": rows,
		"coverage_incomplete_targets": incomplete,
	}, nil
}

// FleetContextFields are the SSVC context fields a fleet import applies to
// every created target; identity fields stay per repository.
var FleetContextFields = []string{"criticality", "system_exposure", "automatable", "mission_impact", "safety_impact"}

// FleetImport turns a GitHub account URL into evidence-attached targets
// through the single-repository import path, so provenance, coverage
// warnings and quotas are identical.
type FleetImport struct {
	Store                   *Store
	GitHub                  repository.GitHub
	Token                   string
	MaxTargets              int
	MaxWorkspaceSourceBytes int64
}

// Import imports up to limit repositories. One repository's failure never
// aborts the rest; a rate limit or a target/quota ceiling stops the
// remainder visibly (stopped_reason). Reruns are idempotent: a repository
// already imported into the workspace is reported, not duplicated.
func (f FleetImport) Import(ctx context.Context, ws, ownerURL string, limit int, includeForks, includeArchived bool,
	shared map[string]string) (map[string]any, error) {
	ref, err := repository.NormalizeOwner(ownerURL)
	if err != nil {
		return nil, err
	}
	var unknown []string
	for key := range shared {
		if !slices.Contains(FleetContextFields, key) {
			unknown = append(unknown, key)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return nil, &repository.Error{Status: 400, Message: "unsupported fleet context fields: " + strings.Join(unknown, ", ")}
	}
	listing, err := f.GitHub.ListOwner(ctx, ref, f.Token, limit, includeForks, includeArchived)
	if err != nil {
		return nil, err
	}
	targets, err := f.Store.Load(ws)
	if err != nil {
		return nil, err
	}
	existing := map[string]Target{}
	for _, t := range targets {
		if url := strings.TrimRight(strOf(t["url"]), "/"); strOf(t["source_kind"]) == "repository" && url != "" {
			existing[strings.ToLower(url)] = t
		}
	}
	results := []map[string]any{}
	imported, stopped := 0, ""
	for _, repo := range listing.Repositories {
		row := map[string]any{"repository": repo.FullName}
		results = append(results, row)
		if stopped != "" {
			row["status"], row["error"] = "not_attempted", stopped
			continue
		}
		if already, ok := existing[strings.ToLower(strings.TrimRight(repo.HTMLURL, "/"))]; ok {
			row["status"], row["target_id"] = "already_imported", already["id"]
			continue
		}
		fields := map[string]any{"name": repo.FullName, "url": repo.HTMLURL}
		for k, v := range shared {
			fields[k] = v
		}
		target, err := f.Store.Add(ws, fields, f.MaxTargets)
		if errors.Is(err, ErrTargetLimit) {
			stopped = err.Error()
			row["status"], row["error"] = "not_attempted", stopped
			continue
		} else if err != nil {
			return nil, &repository.Error{Status: 400, Message: err.Error()}
		}
		id := strOf(target["id"])
		repoRef, err := repository.Normalize(repo.HTMLURL)
		var sbom repository.SBOM
		if err == nil {
			sbom, err = f.GitHub.FetchSBOM(ctx, repoRef, f.Token)
		}
		if err == nil {
			err = f.Store.SaveSource(ws, id, sbom.Content, Source{Format: "spdx",
				Filename: strings.ReplaceAll(repo.FullName, "/", "_") + ".spdx.json", Kind: "repository",
				Provenance: sbom.Provenance}, f.MaxWorkspaceSourceBytes)
		}
		if err != nil {
			_, _ = f.Store.Delete(ws, id) // never leave an evidence-less target behind
			var repoErr *repository.Error
			if errors.As(err, &repoErr) && repoErr.Status == 429 || errors.Is(err, ErrSourceQuota) {
				stopped = err.Error()
			} else if !errors.As(err, &repoErr) {
				return nil, err
			}
			row["status"], row["error"] = "failed", err.Error()
			continue
		}
		imported++
		row["status"], row["target_id"] = "imported", id
		row["component_count"], row["coverage_status"] = sbom.Provenance["component_count"], sbom.Provenance["coverage_status"]
	}
	counts := map[string]int{}
	ids := []any{}
	for _, row := range results {
		counts[row["status"].(string)]++
		if row["status"] == "imported" {
			ids = append(ids, row["target_id"])
		}
	}
	return map[string]any{
		"owner": ref.Owner, "owner_url": ref.NormalizedURL,
		"listing": map[string]any{"total_listed": listing.TotalListed, "skipped_forks": listing.SkippedForks,
			"skipped_archived": listing.SkippedArchived, "truncated": listing.Truncated, "warnings": listing.Warnings},
		"imported": imported, "already_imported": counts["already_imported"], "failed": counts["failed"],
		"not_attempted": counts["not_attempted"], "stopped_reason": stopped, "results": results,
		"imported_target_ids": ids,
	}, nil
}
