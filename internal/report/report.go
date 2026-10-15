// Package report writes the JSON report and the self-contained HTML
// situation report (no external assets; opens offline).
package report

import (
	"cmp"
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/d01ki/PatchTriage-go/internal/decision"
	"github.com/d01ki/PatchTriage-go/internal/model"
	"github.com/d01ki/PatchTriage-go/internal/pipeline"
)

//go:embed report.html.tmpl
var pageTemplate string

var page = template.Must(template.New("report").Parse(pageTemplate))

//go:embed fleet.html.tmpl
var fleetTemplate string

var fleetPage = template.Must(template.New("fleet").Parse(fleetTemplate))

const defaultTitle = "PatchTriage — Situation Report"

var priorityColor = map[string]string{"P1": "#DC2626", "P2": "#D97706", "P3": "#2563EB", "P4": "#6B7280"}

var bodRules = map[string]string{
	"ssvc_only": "SSVC workflow (BOD not applied)", "bod_maximum": "BOD 26-04 maximum",
	"workflow_target_stricter": "workflow target is stricter", "bod_fix_on_upgrade": "BOD fix on system upgrade + workflow target",
	"bod_unresolved_provisional": "provisional: BOD inputs unresolved",
}

var obligationText = map[string]string{
	"remediate": "remediate", "remediate_at_next_major_upgrade": "remediate at next major upgrade", "forensic_triage": "forensic triage",
}

// HTMLOptions are the report's optional inputs.
type HTMLOptions struct {
	Title            string
	Coverage         model.Coverage // nil omits the coverage section
	CoverageWarnings []string
}

func colorOf(priority string) string {
	if c, ok := priorityColor[priority]; ok {
		return c
	}
	return "#6B7280"
}

func priorityOf(f *model.Finding) string {
	if f.Triage == nil || f.Triage.Priority == "" {
		return "P4"
	}
	return f.Triage.Priority
}

// pyFloat renders a float like Python's str().
func pyFloat(v float64) string {
	s := strconv.FormatFloat(v, 'f', -1, 64)
	if !strings.ContainsAny(s, ".e") {
		s += ".0"
	}
	return s
}

func cvssOf(f *model.Finding) *float64 {
	if f.Enrichment.NVDCVSSScore != nil && *f.Enrichment.NVDCVSSScore != 0 {
		return f.Enrichment.NVDCVSSScore
	}
	return f.CVSSScore
}

func kevDisplay(f *model.Finding, compact bool) string {
	pick := func(short, long string) string {
		if compact {
			return short
		}
		return long
	}
	status := f.Enrichment.RetrievalStatus["kev"]
	switch {
	case f.Enrichment.InCISAKEV && status == "listed_stale":
		return pick("YES*", "Listed (catalog stale)")
	case f.Enrichment.InCISAKEV:
		return pick("YES", "Listed")
	case status == "unknown_stale":
		return pick("?", "Unknown (catalog stale)")
	case status == "failed":
		return pick("?", "Unknown (lookup failed)")
	case status == "not_listed":
		return pick("—", "Not listed")
	}
	return pick("?", "Not confirmed")
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

func limited(values []string, n int, empty string) string {
	text := strings.Join(values[:min(n, len(values))], ", ")
	if text == "" {
		text = empty
	}
	if len(values) > n {
		text += " …"
	}
	return text
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

func coverageView(c model.Coverage, warnings []string) map[string]any {
	status := "unknown"
	if s, ok := c["status"].(string); ok && s != "" {
		status = s
	}
	limitedScope := status != "complete"
	var details []string
	for _, item := range []struct{ key, label string }{
		{"total_components", "components"}, {"queryable_components", "queryable"},
		{"queried_components", "queried"}, {"failed_components", "failed"}, {"records", "records consumed"},
	} {
		if v, ok := c[item.key]; ok && v != nil {
			details = append(details, fmt.Sprintf("%s: %v", item.label, v))
		}
	}
	all := append([]string{}, warnings...)
	for _, e := range toStrings(c["errors"]) {
		all = append(all, e)
	}
	if names := toStrings(c["unqueryable_names"]); len(names) > 0 {
		more := ""
		if len(names) > 10 {
			more = fmt.Sprintf(" and %d more", len(names)-10)
		}
		all = append(all, "Not checked: "+strings.Join(names[:min(10, len(names))], ", ")+more)
	}
	ecosystems := toStrings(c["queried_ecosystems"])
	ciOnly := len(ecosystems) > 0 && truthy(c["queried_components"])
	for _, e := range ecosystems {
		if l := strings.ToLower(e); l != "githubactions" && l != "github" {
			ciOnly = false
		}
	}
	if ciOnly {
		all = append(all, "Every component that could be checked was CI/workflow tooling, so no application dependency was assessed.")
	}
	var shown []string
	seen := map[string]bool{}
	for _, w := range all {
		if w != "" && !seen[w] {
			seen[w] = true
			shown = append(shown, w)
		}
	}
	boundary := "The supplied evidence was processed without a recorded coverage failure; this still does not prove the target is vulnerability-free."
	if limitedScope {
		boundary = "The evidence scope is incomplete or provider-reported. A zero finding count is not a clean bill of health."
	}
	return map[string]any{"Limited": limitedScope, "Status": status, "Boundary": boundary,
		"Details": strings.Join(details, " · "), "Warnings": shown}
}

func toStrings(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		var out []string
		for _, item := range x {
			out = append(out, fmt.Sprint(item))
		}
		return out
	}
	return nil
}

func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case int:
		return x != 0
	case float64:
		return x != 0
	}
	return true
}

func explainView(findings []*model.Finding, lead pipeline.Action) map[string]any {
	var pool, candidates []*model.Finding
	for _, f := range findings {
		for _, key := range lead.FindingKeys {
			if f.Key == key {
				candidates = append(candidates, f)
			}
		}
	}
	for _, f := range candidates {
		if priorityOf(f) == lead.TopPriority {
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
	ssvc := model.SSVCAssessment{}
	if f.Triage != nil && f.Triage.SSVC != nil {
		ssvc = *f.Triage.SSVC
	}
	label, ssvcLabel := ssvc.DecisionLabel, ssvc.DecisionLabel
	if label == "" {
		label, ssvcLabel = info["label"], "Unknown"
	}
	var points []map[string]string
	for _, p := range []struct {
		name  string
		point model.DecisionPoint
	}{{"Exploitation", ssvc.Exploitation}, {"System Exposure", ssvc.SystemExposure},
		{"Automatable", ssvc.Automatable}, {"Human Impact", ssvc.HumanImpact}} {
		points = append(points, map[string]string{"Name": p.name, "Label": or(p.point.Label, "Unknown"),
			"Confidence": or(p.point.Confidence, "low"), "Source": or(p.point.Source, "missing")})
	}
	cvss, epss := "Not available", "Not available"
	if v := cvssOf(f); v != nil {
		cvss = fmt.Sprintf("%.1f", *v)
	}
	if v := f.Enrichment.EPSSScore; v != nil {
		epss = fmt.Sprintf("%.1f%%", *v*100)
	}
	fix := "Not supplied"
	if f.Package.FixedVersion != "" {
		fix = "Available"
	}
	var confirm []string
	for _, c := range ssvc.NeedsConfirmation {
		confirm = append(confirm, strings.ReplaceAll(c, "_", " "))
	}
	icons := map[string]string{"confirmed": "✓", "attention": "!", "unknown": "?", "not-observed": "–"}
	var checks []map[string]string
	for _, c := range pipeline.PriorityEvidence(f) {
		icon, ok := icons[c["status"]]
		if !ok {
			icon = "·"
		}
		checks = append(checks, map[string]string{"Status": c["status"], "Icon": icon, "Label": c["label"], "Value": c["value"]})
	}
	return map[string]any{
		"Label": label, "Basis": pipeline.PriorityBasis(f), "Points": points, "Summary": lead.Summary,
		"SSVCLabel": ssvcLabel, "DeadlineDays": lead.DeadlineDays,
		"Signals": []map[string]string{{"Label": "CVSS", "Value": cvss}, {"Label": "EPSS (30 day)", "Value": epss},
			{"Label": "CISA KEV", "Value": kevDisplay(f, false)}, {"Label": "Fix", "Value": fix}},
		"Confirmation": strings.Join(confirm, ", "), "Checks": checks,
	}
}

func or(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func actionView(n int, a pipeline.Action) map[string]any {
	cves := strings.Join(a.CVEs[:min(6, len(a.CVEs))], ", ")
	if len(a.CVEs) > 6 {
		cves += " …"
	}
	view := map[string]any{"N": n, "Color": colorOf(a.TopPriority),
		"Outcome": pipeline.PriorityDefinition(a.TopPriority)["ssvc_outcome"], "Summary": a.Summary,
		"KEVCount": a.KEVCount, "CVEs": cves, "CVECount": len(a.CVEs), "DeadlineDays": a.DeadlineDays}
	if p := a.BOD2604; len(p) > 0 {
		scope := "reference only"
		if p["applied"] == true {
			scope = fmt.Sprint(p["applicability"])
		}
		view["BOD"] = map[string]any{"Label": p["label"], "Provisional": p["status"] != "resolved",
			"Unresolved": p["unresolved_findings"], "Forensic": p["forensic_triage"] == true, "Scope": scope}
	}
	if a.EffectiveRule != "" {
		days := "no numeric deadline"
		if a.EffectiveDeadlineDays != nil {
			days = fmt.Sprintf("%dd", *a.EffectiveDeadlineDays)
		}
		note := or(bodRules[a.EffectiveRule], a.EffectiveRule)
		var extra []string
		for _, o := range a.Obligations {
			if o != "remediate" {
				extra = append(extra, or(obligationText[o], o))
			}
		}
		if len(extra) > 0 {
			note += "; also " + strings.Join(extra, ", ")
		}
		view["Effective"] = map[string]string{"Days": days, "Note": note}
	}
	return view
}

func bodView(findings []*model.Finding) map[string]any {
	s := decision.SummarizePolicy(findings)
	if s["evaluated"] == 0 {
		return nil
	}
	scope := strings.Join(s["applicability"].([]string), ", ")
	if scope == "" {
		scope = "unknown"
	}
	applied := "reference only: not applied to the effective deadline"
	if s["applied"] == true {
		applied = "applied to the effective deadline"
	}
	var outcomes []string
	counts := s["outcomes"].(map[string]int)
	for _, key := range []string{"FSU", "60D", "14D", "3D", "3DF"} {
		if counts[key] > 0 {
			outcomes = append(outcomes, fmt.Sprintf("%s %d", decision.Outcomes[key].Label, counts[key]))
		}
	}
	sources := decision.Sources
	return map[string]any{"Policy": s["policy"], "Scope": scope, "Applied": applied, "Resolved": s["resolved"],
		"Evaluated": s["evaluated"], "Outcomes": strings.Join(outcomes, " · "), "Unresolved": s["unresolved"],
		"Forensic": s["forensic_triage"], "DirectiveURL": sources["directive"]["url"], "Issued": sources["directive"]["issued"],
		"GuidanceURL": sources["implementation_guidance"]["url"], "ModelURL": sources["decision_model"]["url"],
		"Retrieved": sources["directive"]["retrieved"]}
}

func evalView(rows []pipeline.EvalRow, total int) map[string]any {
	if len(rows) == 0 {
		return nil
	}
	var body []map[string]any
	for _, r := range rows {
		bestKEV := max(r.KEVBaseline, r.KEVEPSS, r.KEVKEV, r.KEVSSVC)
		bestUrgent := max(r.UrgentCVSS, r.UrgentEPSS, r.UrgentKEV, r.UrgentSSVC)
		var cells []map[string]any
		for _, v := range []int{r.KEVBaseline, r.KEVEPSS, r.KEVKEV, r.KEVSSVC} {
			cells = append(cells, map[string]any{"Win": v == bestKEV, "Text": fmt.Sprintf("%d/%d", v, r.KEVTotal)})
		}
		for _, v := range []int{r.UrgentCVSS, r.UrgentEPSS, r.UrgentKEV, r.UrgentSSVC} {
			cells = append(cells, map[string]any{"Win": v == bestUrgent, "Text": fmt.Sprintf("%d/%d", v, r.UrgentTotal)})
		}
		body = append(body, map[string]any{"K": r.K, "Cells": cells})
	}
	lead := rows[0]
	outcome := pipeline.EvaluationOutcome(lead, total)
	kevCoverage, urgentCoverage := "n/a", "n/a"
	if lead.KEVTotal > 0 {
		kevCoverage = fmt.Sprintf("%.1f%%", outcome["kev_coverage_pct"])
	}
	if lead.UrgentTotal > 0 {
		urgentCoverage = fmt.Sprintf("%.1f%%", outcome["urgent_coverage_pct"])
	}
	return map[string]any{"K": lead.K, "Reduction": fmt.Sprintf("%.1f%%", outcome["review_reduction_pct"]),
		"Reviewed": outcome["reviewed"], "Total": total, "KEVCoverage": kevCoverage, "KEVSSVC": lead.KEVSSVC,
		"KEVTotal": lead.KEVTotal, "UrgentCoverage": urgentCoverage, "UrgentSSVC": lead.UrgentSSVC,
		"UrgentTotal": lead.UrgentTotal, "Rows": body}
}

func isWebURL(u string) bool {
	return strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "http://")
}

func findingView(f *model.Finding) map[string]any {
	e, priority := f.Enrichment, priorityOf(f)
	cvss, epss := "–", "–"
	if v := cvssOf(f); v != nil && *v != 0 {
		cvss = pyFloat(*v)
	}
	if e.EPSSScore != nil {
		epss = fmt.Sprintf("%.3f", *e.EPSSScore)
	}
	var badges []map[string]string
	for _, a := range e.VendorAdvisories[:min(4, len(e.VendorAdvisories))] {
		badge := map[string]string{"Label": strings.ToUpper(a.Source) + ":" + a.AdvisoryID}
		if isWebURL(a.URL) {
			badge["URL"] = a.URL
		}
		badges = append(badges, badge)
	}
	view := map[string]any{"Color": colorOf(priority), "Outcome": pipeline.PriorityDefinition(priority)["ssvc_outcome"],
		"VulnID": f.VulnID, "Package": f.Package.Name + " " + f.Package.Version, "VersionSource": f.Package.VersionSource,
		"CVSS": cvss, "EPSS": epss, "KEV": kevDisplay(f, true), "Badges": badges, "Action": "—",
		"Asset": f.Asset.Identifier, "BOD": "—"}
	if t := f.Triage; t != nil {
		view["Action"] = t.Action
		view["Rationale"] = truncate(t.Rationale, 160)
		if t.Audit != nil {
			view["Audit"] = map[string]any{"Verified": t.Audit["verified"] == true,
				"Flags": strings.Join(toStrings(t.Audit["flags"]), ", ")}
		}
		if p := t.BOD2604; p != nil {
			if p.Status == "resolved" && p.OutcomeLabel != nil {
				view["BOD"] = *p.OutcomeLabel
			} else if p.ProvisionalLabel != nil {
				var names []string
				for _, name := range p.UnresolvedInputs {
					names = append(names, strings.ReplaceAll(name, "_", " "))
				}
				view["BOD"] = fmt.Sprintf("unresolved (%s); provisional %s", strings.Join(names, ", "), *p.ProvisionalLabel)
			}
		}
	}
	return view
}

// RenderHTML renders the self-contained situation report.
func RenderHTML(findings []*model.Finding, actions []pipeline.Action, rows []pipeline.EvalRow, o HTMLOptions) (string, error) {
	counts := map[string]int{"P1": 0, "P2": 0, "P3": 0, "P4": 0}
	kev := 0
	advisoryKeys := map[[2]string]bool{}
	var vendorSources, vendorErrors, retrievalErrors []string
	for _, f := range findings {
		counts[priorityOf(f)]++
		if f.Enrichment.InCISAKEV {
			kev++
		}
		for _, a := range f.Enrichment.VendorAdvisories {
			advisoryKeys[[2]string{a.Source, a.AdvisoryID}] = true
		}
		vendorSources = append(vendorSources, f.Enrichment.VendorSourcesChecked...)
		vendorErrors = append(vendorErrors, f.Enrichment.VendorLookupErrors...)
		retrievalErrors = append(retrievalErrors, f.Enrichment.RetrievalErrors...)
	}
	total := len(findings)
	view := map[string]any{
		"Title": or(o.Title, defaultTitle), "Now": time.Now().UTC().Format("2006-01-02 15:04 UTC"), "Total": total,
		"ActionCount": len(actions), "KEVCount": kev, "AdvisoryCount": len(advisoryKeys),
		"P1": counts["P1"], "P2": counts["P2"], "P3": counts["P3"], "P4": counts["P4"],
	}
	var spine, guide []map[string]string
	for _, p := range []string{"P1", "P2", "P3", "P4"} {
		info := pipeline.PriorityDefinition(p)
		guide = append(guide, map[string]string{"Color": priorityColor[p], "Outcome": info["ssvc_outcome"],
			"Description": info["description"], "Window": info["window"]})
		if total > 0 && counts[p] > 0 {
			spine = append(spine, map[string]string{"Width": fmt.Sprintf("%.1f%%", float64(counts[p])/float64(total)*100),
				"Color": priorityColor[p], "Title": fmt.Sprintf("%s: %d", info["ssvc_outcome"], counts[p])})
		}
	}
	view["Spine"], view["Guide"] = spine, guide
	if q := pipeline.DecisionQuality(findings); q["points_total"] != 0 {
		view["Quality"] = map[string]any{"Authoritative": q["authoritative"], "PointsTotal": q["points_total"],
			"Pct": pyFloat(q["authoritative_pct"].(float64)), "Assumed": q["assumed"],
			"NeedsConfirmation": q["needs_confirmation"], "DeEscalated": q["de_escalated"], "Sources": q["sources"]}
	}
	limitedScope := o.Coverage != nil && o.Coverage["status"] != "complete"
	if total == 0 {
		heading, detail := "No vulnerability records were reported",
			"No SSVC assessment was required. Confirm that the original scan covered the intended target and review the evidence coverage below."
		if limitedScope {
			heading, detail = "No vulnerability findings — evidence coverage is limited",
				"At least one provider, component, selector, or scan-scope boundary was not complete. Do not interpret this result as a clean target."
		}
		view["Empty"] = map[string]string{"Heading": heading, "Detail": detail}
	} else if len(actions) > 0 {
		if explain := explainView(findings, actions[0]); explain != nil {
			view["Explain"] = explain
		}
	}
	if o.Coverage != nil {
		view["Coverage"] = coverageView(o.Coverage, o.CoverageWarnings)
	}
	var actionRows []map[string]any
	for i, a := range actions {
		actionRows = append(actionRows, actionView(i+1, a))
	}
	view["Actions"] = actionRows
	if b := bodView(findings); b != nil {
		view["BOD"] = b
	}
	if e := evalView(rows, total); e != nil {
		view["Eval"] = e
	}
	var advisories []map[string]string
	seen := map[[3]string]bool{}
	for _, f := range findings {
		for _, a := range f.Enrichment.VendorAdvisories {
			key := [3]string{f.VulnID, a.Source, a.AdvisoryID}
			if seen[key] {
				continue
			}
			seen[key] = true
			row := map[string]string{"CVE": f.VulnID, "Label": strings.ToUpper(a.Source) + " · " + a.AdvisoryID,
				"Title": a.Title, "Products": limited(a.Products, 3, "—"), "Fixes": limited(a.FixedVersions, 3, "—")}
			if isWebURL(a.URL) {
				row["URL"] = a.URL
			}
			advisories = append(advisories, row)
		}
	}
	view["Advisories"] = advisories
	var connectorErrors []string
	for _, e := range uniqueSorted(retrievalErrors) {
		connectorErrors = append(connectorErrors, "Threat evidence: "+e)
	}
	for _, e := range uniqueSorted(vendorErrors) {
		connectorErrors = append(connectorErrors, "Vendor evidence: "+e)
	}
	view["ConnectorErrors"] = connectorErrors
	ordered := append([]*model.Finding(nil), findings...)
	sort.SliceStable(ordered, func(i, j int) bool { return decision.OrderLess(ordered[i], ordered[j]) })
	var findingRows []map[string]any
	for _, f := range ordered {
		findingRows = append(findingRows, findingView(f))
	}
	view["Findings"] = findingRows
	if sources := uniqueSorted(vendorSources); len(sources) > 0 {
		var upper []string
		for _, s := range sources {
			upper = append(upper, strings.ToUpper(s))
		}
		view["FooterSources"] = " · " + strings.Join(upper, " · ")
	}
	var b strings.Builder
	if err := page.Execute(&b, view); err != nil {
		return "", err
	}
	return b.String(), nil
}

// WriteHTML renders the report into path, creating parent directories.
func WriteHTML(path string, findings []*model.Finding, actions []pipeline.Action, rows []pipeline.EvalRow, o HTMLOptions) error {
	out, err := RenderHTML(findings, actions, rows, o)
	if err != nil {
		return err
	}
	return writeFile(path, []byte(out))
}

// WriteJSON writes the full JSON report into path.
func WriteJSON(path string, a *pipeline.Assessment) error {
	raw, err := json.MarshalIndent(pipeline.ReportJSON(a), "", "  ")
	if err != nil {
		return err
	}
	return writeFile(path, raw)
}

func writeFile(path string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, content, 0o644)
}

// ------------------------------------------------------------ fleet

var fleetOutcomes = []struct{ key, label, color string }{
	{"immediate", "Immediate", "#DC2626"}, {"out_of_cycle", "Out-of-Cycle", "#D97706"},
	{"scheduled", "Scheduled", "#2563EB"}, {"defer", "Defer", "#6B7280"},
}

type fleetCount struct {
	Label, Color string
	Count        int
}

type fleetQueueRow struct {
	Color, Outcome, Target, Package, Versions, Summary string
	Deadline, KEV, Findings                            any
}

type fleetTargetRow struct {
	Name, State, Coverage, ReportURL string
	Assessed                         bool
	Findings, KEV                    any
	Chips                            []fleetCount
}

func anyInt(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case float64:
		return int(x)
	}
	return 0
}

func anyText(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

func orDash(m map[string]any, key string) any {
	if v, ok := m[key]; ok && v != nil {
		return v
	}
	return "—"
}

func mapsOf(v any) []map[string]any {
	var out []map[string]any
	switch list := v.(type) {
	case []map[string]any:
		return list
	case []any:
		for _, item := range list {
			if m, ok := item.(map[string]any); ok {
				out = append(out, m)
			}
		}
	}
	return out
}

// RenderFleetHTML renders a fleet rollup (web.AggregateFleet) as one
// self-contained page. It adds nothing of its own: every number shown was
// decided per target by the deterministic SSVC engine.
func RenderFleetHTML(rollup map[string]any, title string) (string, error) {
	if title == "" {
		title = "PatchTriage — Fleet Report"
	}
	outcomes, _ := rollup["outcomes"].(map[string]int)
	if outcomes == nil {
		outcomes = map[string]int{}
		if m, ok := rollup["outcomes"].(map[string]any); ok {
			for k, v := range m {
				outcomes[k] = anyInt(v)
			}
		}
	}
	view := map[string]any{
		"Title": title, "Assessed": anyInt(rollup["targets_assessed"]), "Total": anyInt(rollup["targets_total"]),
		"Findings": anyInt(rollup["findings_total"]), "KEV": anyInt(rollup["kev_total"]),
		"GeneratedAt": anyText(rollup["generated_at"]), "QueueTruncated": rollup["queue_truncated"] == true,
		"Incomplete": anyInt(rollup["coverage_incomplete_targets"]), "Unassessed": anyInt(rollup["targets_unassessed"]),
	}
	var cards []fleetCount
	for _, o := range fleetOutcomes {
		cards = append(cards, fleetCount{o.label, o.color, outcomes[o.key]})
	}
	view["Cards"] = cards
	var queue []fleetQueueRow
	for _, e := range mapsOf(rollup["queue"]) {
		priority := anyText(e["top_priority"])
		if priority == "" {
			priority = "P4"
		}
		outcome := anyText(e["outcome_label"])
		if outcome == "" {
			outcome = priority
		}
		versions := ""
		if installed, target := anyText(e["installed_version"]), anyText(e["target_version"]); installed != "" || target != "" {
			versions = cmp.Or(installed, "?") + " → " + cmp.Or(target, "?")
		}
		queue = append(queue, fleetQueueRow{Color: colorOf(priority), Outcome: outcome, Target: anyText(e["target_name"]),
			Package: anyText(e["package"]), Versions: versions, Summary: anyText(e["summary"]),
			Deadline: e["deadline_days"], KEV: anyInt(e["kev_count"]), Findings: e["finding_count"]})
	}
	view["Queue"] = queue
	var targets []fleetTargetRow
	for _, t := range mapsOf(rollup["targets"]) {
		row := fleetTargetRow{Name: anyText(t["name"]), Assessed: t["assessed"] == true, ReportURL: anyText(t["report_url"]),
			Findings: orDash(t, "total"), KEV: orDash(t, "kev")}
		if row.Assessed {
			row.State = cmp.Or(strings.ReplaceAll(anyText(t["result_state"]), "_", " "), "assessed")
			if coverage := anyText(t["coverage_status"]); coverage != "complete" {
				row.Coverage = coverage
			}
			counts, _ := t["outcomes"].(map[string]any)
			for _, o := range fleetOutcomes {
				row.Chips = append(row.Chips, fleetCount{Color: o.color, Count: anyInt(counts[o.key])})
			}
		}
		targets = append(targets, row)
	}
	view["Targets"] = targets
	var b strings.Builder
	if err := fleetPage.Execute(&b, view); err != nil {
		return "", err
	}
	return b.String(), nil
}

// WriteFleetHTML writes the fleet report into path.
func WriteFleetHTML(path string, rollup map[string]any, title string) error {
	out, err := RenderFleetHTML(rollup, title)
	if err != nil {
		return err
	}
	return writeFile(path, []byte(out))
}
