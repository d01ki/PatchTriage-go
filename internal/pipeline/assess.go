package pipeline

// One assessment core shared by the CLI and the web GUI:
//
//	ingest -> dedup -> context -> enrich -> SSVC -> audit -> BOD 26-04 -> plan -> evaluate
//
// Entry points only gather inputs and present the result, so the same
// evidence and context always reach the same decisions.

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/d01ki/PatchTriage-go/internal/decision"
	"github.com/d01ki/PatchTriage-go/internal/enrich"
	"github.com/d01ki/PatchTriage-go/internal/ingest"
	"github.com/d01ki/PatchTriage-go/internal/model"

	"errors"

	"time"
)

// Options are the inputs of one assessment besides the evidence files.
type Options struct {
	Format string       // force a scanner format; "" sniffs
	Asset  *model.Asset // a named asset replaces the scanner's; an unnamed one fills supplied context
	// Inventory is an asset inventory YAML path.
	Inventory string
	// SSVCOverrides holds analyst-confirmed inputs keyed by finding key.
	SSVCOverrides    map[string]map[string]string
	DeclaredCoverage model.Coverage
	ProviderStatus   string
	Snapshot         *enrich.Snapshot // bundled evidence instead of live providers
	Enrich           enrich.Options
	OSV              *ingest.OSVClient
	Limit            int
	// Triage selects an AI backend for the reported subset; zero is rules.
	Triage     TriageOptions
	Progress   func(string)
	OnCoverage func(model.Coverage)
}

// Assessment is the result of one assessment run.
type Assessment struct {
	Findings []*model.Finding // every finding, with SSVC and policy records
	Subset   []*model.Finding // reported findings: top-N after SSVC screening
	Actions  []Action
	EvalRows []EvalRow
	Coverage model.Coverage
	Audit    AuditSummary
}

func asInt(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case float64:
		return int(x)
	}
	return 0
}

func asStrings(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, item := range x {
			out = append(out, fmt.Sprint(item))
		}
		return out
	}
	return nil
}

func asList(v any) ([]any, bool) {
	rv := reflect.ValueOf(v)
	if v == nil || rv.Kind() != reflect.Slice {
		return nil, false
	}
	out := make([]any, rv.Len())
	for i := range out {
		out[i] = rv.Index(i).Interface()
	}
	return out, true
}

// CombineCoverage merges declared and observed coverage without letting one
// successful parser erase a boundary.
func CombineCoverage(declared, observed model.Coverage, providerStatus string) model.Coverage {
	coverage := model.Coverage{}
	for k, v := range declared {
		coverage[k] = v
	}
	for k, v := range observed {
		coverage[k] = v
	}
	complete := observed["complete"] == true && declared["complete"] != false &&
		(providerStatus == "" || providerStatus == "complete")
	status := "incomplete"
	switch {
	case providerStatus != "" && providerStatus != "complete":
		status = providerStatus
	case complete:
		status = "complete"
	}
	coverage["status"], coverage["complete"] = status, status == "complete"
	return coverage
}

// MergeFileCoverage combines per-file coverage; one incomplete file keeps
// the whole result bounded.
func MergeFileCoverage(coverages []model.Coverage) model.Coverage {
	if len(coverages) == 1 {
		return coverages[0]
	}
	var types []string
	complete := true
	for _, c := range coverages {
		kind, _ := c["source_type"].(string)
		if kind == "" {
			kind = "unknown"
		}
		types = append(types, kind)
		complete = complete && c["complete"] == true
	}
	merged := model.Coverage{"source_type": strings.Join(types, "+"), "complete": complete}
	for _, c := range coverages {
		keys := make([]string, 0, len(c))
		for k := range c {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := c[k]
			if k == "source_type" || k == "complete" {
				continue
			}
			switch x := v.(type) {
			case bool:
			case int, float64:
				merged[k] = asInt(merged[k]) + asInt(x)
			default:
				items, isList := asList(v)
				if !isList {
					continue
				}
				existing, _ := asList(merged[k])
				if existing == nil {
					existing = []any{}
				}
				for _, item := range items {
					seen := false
					for _, e := range existing {
						seen = seen || reflect.DeepEqual(e, item)
					}
					if !seen {
						existing = append(existing, item)
					}
				}
				merged[k] = existing
			}
		}
	}
	return merged
}

// ResultMessage says what was actually checked, not just that coverage was
// bounded: "no findings" reads as safety, so skipped components are named.
func ResultMessage(findings, actions int, incomplete bool, status string, coverage model.Coverage) string {
	total, checked := asInt(coverage["total_components"]), asInt(coverage["queried_components"])
	skipped, inferred := asInt(coverage["unqueryable_components"]), asInt(coverage["inferred_components"])
	names, ecosystems := asStrings(coverage["unqueryable_names"]), asStrings(coverage["queried_ecosystems"])
	inferredNote := ""
	if inferred > 0 {
		inferredNote = fmt.Sprintf(" %d component(s) had only a declared constraint or none, so each was checked at a "+
			"registry release chosen from it (the oldest a lower-bounded range permits, otherwise the newest), not "+
			"necessarily the deployed version.", inferred)
	}
	if findings > 0 {
		switch {
		case incomplete && actions > 0 && total > 0:
			return fmt.Sprintf("Assessment completed, but evidence coverage is bounded: %d of %d component(s) could be checked.",
				checked, total) + inferredNote
		case incomplete && actions > 0:
			return "Assessment completed with bounded or incomplete evidence coverage."
		case actions == 0:
			return "Assessment completed, but no remediation action could be built."
		}
		return ""
	}
	if inferred > 0 && total > 0 && skipped == 0 {
		return fmt.Sprintf("%d of %d component(s) were checked against OSV and none had a known vulnerability.", checked, total) +
			inferredNote + " Commit a lockfile or upload scanner output to assess the exact deployed versions."
	}
	if skipped > 0 && total > 0 {
		detail := fmt.Sprintf("%d of %d component(s) were checked against OSV and none had a known vulnerability. "+
			"%d component(s) could not be checked because the source lists them without a resolved version", checked, total, skipped)
		if len(names) > 0 {
			detail += ": " + strings.Join(names[:min(5, len(names))], ", ")
			if len(names) > 5 {
				detail += fmt.Sprintf(" and %d more", len(names)-5)
			}
		}
		if inferred > 0 {
			detail += "." + strings.TrimSuffix(inferredNote, ".")
		}
		ciOnly := checked > 0
		for _, e := range ecosystems {
			if l := strings.ToLower(e); l != "githubactions" && l != "github" {
				ciOnly = false
			}
		}
		if ciOnly {
			detail += ". Everything that could be checked was CI/workflow tooling, so no application dependency was actually assessed"
		}
		return detail + ". Commit a lockfile (uv.lock, poetry.lock, package-lock.json, pinned requirements.txt) " +
			"or upload scanner output for full coverage."
	}
	if status == "provider_reported" {
		return "No findings were reported. The evidence scope is what the provider chose to report and was not independently verified."
	}
	if incomplete {
		return "No findings were reported, but dependency or selector coverage is incomplete."
	}
	return "The attached evidence reported no vulnerability findings."
}

// load reads one file, applying target context the same way for every
// caller: a named asset replaces the scanner's asset; an unnamed one fills
// in only the context values actually supplied.
func load(ctx context.Context, path string, o Options) (ingest.LoadResult, error) {
	replace := o.Asset != nil && o.Asset.Identifier != ""
	var asset *model.Asset
	if replace {
		asset = o.Asset
	}
	loaded, err := ingest.LoadFile(ctx, path, o.Format, asset, o.OSV)
	if err != nil || o.Asset == nil || replace {
		return loaded, err
	}
	a := o.Asset
	for i := range loaded.Findings {
		target := &loaded.Findings[i].Asset
		if a.Criticality != "" && a.Criticality != "unknown" {
			target.Criticality = a.Criticality
		}
		for _, b := range []struct{ from, to **bool }{
			{&a.InternetExposed, &target.InternetExposed}, {&a.Reachable, &target.Reachable},
			{&a.RuntimeObserved, &target.RuntimeObserved},
		} {
			if *b.from != nil {
				*b.to = *b.from
			}
		}
		for _, s := range []struct{ from, to *string }{
			{&a.SystemExposure, &target.SystemExposure}, {&a.Automatable, &target.Automatable},
			{&a.MissionImpact, &target.MissionImpact}, {&a.SafetyImpact, &target.SafetyImpact},
			{&a.PubliclyExposed, &target.PubliclyExposed}, {&a.BOD2604Applicability, &target.BOD2604Applicability},
		} {
			if *s.from != "" && *s.from != "unknown" {
				*s.to = *s.from
			}
		}
	}
	return loaded, nil
}

// Assess runs the full assessment for one target context.
func Assess(ctx context.Context, files []string, o Options) (*Assessment, error) {
	progress := o.Progress
	if progress == nil {
		progress = func(string) {}
	}
	var raw []model.RawFinding
	var fileCoverage []model.Coverage
	for _, path := range files {
		progress(fmt.Sprintf("reading %s (SBOMs are resolved online via OSV.dev)...", path))
		loaded, err := load(ctx, path, o)
		if err != nil {
			return nil, err
		}
		progress(fmt.Sprintf("ingested %5d findings from %s", len(loaded.Findings), path))
		raw = append(raw, loaded.Findings...)
		fileCoverage = append(fileCoverage, loaded.Coverage)
	}
	observed := model.Coverage{}
	if len(fileCoverage) > 0 {
		observed = MergeFileCoverage(fileCoverage)
	}
	coverage := CombineCoverage(o.DeclaredCoverage, observed, o.ProviderStatus)
	if o.OnCoverage != nil {
		o.OnCoverage(coverage)
	}

	findings := ingest.Dedup(raw)
	progress(fmt.Sprintf("%d raw -> %d deduplicated findings", len(raw), len(findings)))
	for _, f := range findings {
		inputs := map[string]string{}
		for k, v := range o.SSVCOverrides[f.Key] {
			if k == "exploitation" || k == "automatable" {
				inputs[k] = v
			}
		}
		if len(o.SSVCOverrides[f.Key]) > 0 {
			f.SSVCInputs = inputs
		}
	}
	// Context before triage so every decision sees it.
	if o.Inventory != "" {
		inventory, err := ingest.LoadInventory(o.Inventory)
		if err != nil {
			return nil, err
		}
		matched, err := ingest.ApplyContext(findings, inventory)
		if err != nil {
			return nil, err
		}
		progress(fmt.Sprintf("asset context applied to %d findings from %s", matched, o.Inventory))
	}
	if len(findings) > 0 {
		if o.Snapshot != nil {
			enrich.EnrichFromSnapshot(findings, *o.Snapshot)
		} else {
			progress("enriching with EPSS / CISA KEV / Vulnrichment / NVD...")
			if err := enrich.Enrich(ctx, findings, o.Enrich); err != nil {
				return nil, err
			}
		}
	}

	// Deterministic SSVC screening comes before the limit: scanner severity
	// alone must never exclude a low-CVSS KEV or context-urgent finding.
	for _, f := range findings {
		f.Triage = decision.Triage(f)
	}
	subset := append([]*model.Finding(nil), findings...)
	sort.SliceStable(subset, func(i, j int) bool { return decision.OrderLess(subset[i], subset[j]) })
	if o.Limit > 0 && o.Limit < len(subset) {
		subset = subset[:o.Limit]
	}
	if err := triageSubset(ctx, subset, o.Triage, progress); err != nil {
		return nil, err
	}
	audit := AuditAll(subset)
	// BOD 26-04 is evaluated next to, never instead of, the SSVC result.
	decision.ApplyPolicy(findings)
	return &Assessment{Findings: findings, Subset: subset, Actions: BuildPlan(subset),
		EvalRows: Evaluate(subset, nil), Coverage: coverage, Audit: audit}, nil
}

// batchPoll is how often a Message Batches run is polled.
var batchPoll = 15 * time.Second

func triageSubset(ctx context.Context, subset []*model.Finding, o TriageOptions, progress func(string)) error {
	backend := o.Backend
	switch {
	case o.Batch && (backend == "ai" || backend == "claude"):
		provider := o.Provider
		if backend == "claude" {
			provider = "anthropic"
		}
		return RunTriageBatch(ctx, subset, o.Model, provider, batchPoll, progress)
	case o.Batch:
		return errors.New("--batch is supported only with the 'ai' backend and the Anthropic provider")
	case backend == "" || backend == "rules":
		return nil
	}
	b, err := GetBackend(o)
	if err != nil {
		return err
	}
	workers := max(1, o.Jobs)
	progress(fmt.Sprintf("triaging %d findings via '%s' (%d workers)...", len(subset), backend, workers))
	return RunTriage(ctx, subset, b, workers, nil)
}

// ReportJSON is the full JSON report (the CLI's -o output).
func ReportJSON(a *Assessment) map[string]any {
	findings := a.Findings
	if findings == nil {
		findings = []*model.Finding{}
	}
	return map[string]any{"findings": findings, "actions": a.Actions, "evaluation": a.EvalRows,
		"response_policy": decision.SummarizePolicy(a.Findings), "coverage": a.Coverage}
}

// AssetFromTarget builds the exact asset context the SSVC engine consumes
// from a GUI target record. Automatable is vulnerability-specific, so a
// target never applies one value to every finding.
func AssetFromTarget(target map[string]any) model.Asset {
	text := func(key, fallback string) string {
		if v, ok := target[key].(string); ok && v != "" {
			return v
		}
		return fallback
	}
	flag := func(key string) *bool {
		if v, ok := target[key].(bool); ok {
			return &v
		}
		return nil
	}
	a := model.NewAsset(text("name", ""))
	switch {
	case target["source_kind"] == "repository":
		a.Kind = "repository"
	case target["source_format"] == "cyclonedx" || target["source_format"] == "spdx":
		a.Kind = "sbom"
	default:
		a.Kind = "host"
	}
	a.Criticality = text("criticality", "unknown")
	a.InternetExposed, a.Reachable, a.RuntimeObserved = flag("internet_exposed"), flag("reachable"), flag("runtime_observed")
	a.SystemExposure, a.MissionImpact = text("system_exposure", "unknown"), text("mission_impact", "unknown")
	a.SafetyImpact, a.PubliclyExposed = text("safety_impact", "unknown"), text("publicly_exposed", "unknown")
	a.BOD2604Applicability = text("bod2604_applicability", "unknown")
	a.ContextSources = append([]string{}, asStrings(target["context_sources"])...)
	return a
}
