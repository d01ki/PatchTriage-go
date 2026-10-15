// Command patchtriage turns scanner evidence into SSVC patch deployment
// decisions: run (scriptable pipeline), demo (offline demonstration),
// verify (conformance proof), serve (GUI), and the guided setup, start and
// remediate workflows.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"

	"github.com/d01ki/PatchTriage-go/data"
	"github.com/d01ki/PatchTriage-go/internal/ai"
	"github.com/d01ki/PatchTriage-go/internal/enrich"
	"github.com/d01ki/PatchTriage-go/internal/model"
	"github.com/d01ki/PatchTriage-go/internal/pipeline"
	"github.com/d01ki/PatchTriage-go/internal/report"
	"github.com/d01ki/PatchTriage-go/internal/repository"
	"github.com/d01ki/PatchTriage-go/internal/validation"
	"github.com/d01ki/PatchTriage-go/internal/web"
)

const usage = `usage: patchtriage <command> [options]

commands:
  run FILES...   scanner JSON (Trivy/Grype/OSV) or CycloneDX/SPDX SBOM -> decisions and reports
  demo           fully offline demo with bundled evidence
  verify         offline SSVC conformance and reproducibility proof
  serve          GUI console (default http://127.0.0.1:8765)
  fleet URL      import a GitHub account's repositories and build one fleet queue
  remediate      prepare one dependency patch in an isolated local clone (guided without arguments)
  setup          first-run wizard: AI provider, API keys and default backend
  start          guided run: answer a few questions, get a prioritized patch plan
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(stderr, usage)
		return 2
	}
	// Saved keys fill in whatever the environment does not already set.
	ai.ApplyToEnv(ai.LoadConfig())
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	var err error
	switch args[0] {
	case "run":
		var cfg runConfig
		if cfg, err = parseRun(args[1:]); err == nil {
			_, err = execute(ctx, cfg, stdout)
		}
	case "demo":
		err = demo(ctx, args[1:], stdout)
	case "verify":
		err = verify(args[1:], stdout)
	case "serve":
		err = serve(ctx, args[1:])
	case "fleet":
		err = fleet(ctx, args[1:], stdout)
	case "remediate":
		err = remediate(args[1:], stdout)
	case "setup":
		err = setup(ctx, stdout)
	case "start":
		err = start(ctx, stdout)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n%s", args[0], usage)
		return 2
	}
	var code exitCode
	switch {
	case errors.As(err, &code):
		return int(code)
	case err != nil:
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stderr, "error:", err)
		}
		return 1
	}
	return 0
}

// parseInterleaved parses flags that may follow positional arguments.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return positional, nil
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
}

type runConfig struct {
	files        []string
	options      pipeline.Options
	output, html string
	warnings     []string // repository coverage warnings shown in the HTML report
}

// assess runs the pipeline; tests replace it.
var assess = pipeline.Assess

func firstEnv(names ...string) string {
	for _, name := range names {
		if v := os.Getenv(name); v != "" {
			return v
		}
	}
	return ""
}

func parseRun(args []string) (runConfig, error) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	format := fs.String("fmt", "", "force format: trivy|grype|osv")
	assets := fs.String("assets", "", "asset inventory YAML")
	assetID := fs.String("asset-id", "", "override asset identifier")
	criticality := fs.String("criticality", "unknown", "asset criticality override")
	exposed := fs.Bool("exposed", false, "asset is internet exposed")
	notExposed := fs.Bool("not-exposed", false, "asset is not internet exposed")
	reachable := fs.Bool("reachable", false, "static analysis says the vulnerable path is reachable")
	notReachable := fs.Bool("not-reachable", false, "static analysis says the vulnerable path is not reachable")
	runtime := fs.Bool("runtime-observed", false, "component or path observed at runtime")
	notRuntime := fs.Bool("not-runtime-observed", false, "component or path not observed at runtime")
	choices := map[string]*string{
		"system_exposure":       fs.String("ssvc-exposure", "unknown", "SSVC System Exposure: small|controlled|open|unknown"),
		"automatable":           fs.String("ssvc-automatable", "unknown", "SSVC Automatable: yes|no|unknown"),
		"mission_impact":        fs.String("ssvc-mission-impact", "unknown", "SSVC Mission Impact: degraded|mef_support_crippled|mef_failure|mission_failure|unknown"),
		"safety_impact":         fs.String("ssvc-safety-impact", "unknown", "SSVC Safety Impact: negligible|marginal|critical|catastrophic|unknown"),
		"bod2604_applicability": fs.String("bod2604", "unknown", "CISA BOD 26-04 applicability: required|voluntary|not_applicable|unknown"),
		"publicly_exposed":      fs.String("publicly-exposed", "unknown", "CISA BOD 26-04 Publicly Exposed: yes|no|unknown (not SSVC System Exposure)"),
	}
	noNVD := fs.Bool("no-nvd", false, "skip NVD (EPSS/KEV only)")
	noVulnrichment := fs.Bool("no-vulnrichment", false, "skip CISA Vulnrichment decision points")
	nvdKey := fs.String("nvd-api-key", os.Getenv("NVD_API_KEY"), "NVD API key")
	vendorSources := fs.String("vendor-sources", "auto", "vendor/exploit sources: auto|all|msrc,rhsa,usn,debian,ghsa,exploitdb")
	noVendor := fs.Bool("no-vendor-advisories", false, "skip vendor advisory lookups")
	githubToken := fs.String("github-token", firstEnv("GITHUB_TOKEN", "GH_TOKEN"), "GitHub token (raises GHSA rate limits)")
	triage := fs.String("triage", "", "triage backend: rules|ai|cascade (default: your setup choice, else rules)")
	provider := fs.String("provider", "", "AI provider: anthropic|openai|openai-compatible|ollama")
	aiBaseURL := fs.String("ai-base-url", "", "OpenAI-compatible API base URL (for gateways/local models)")
	modelName := fs.String("model", "", "model id (ai: model; cascade: screening model)")
	escalationModel := fs.String("escalation-model", "", "cascade only: frontier model for escalated findings")
	jobs := fs.Int("jobs", 4, "parallel API calls for ai/cascade")
	batch := fs.Bool("batch", false, "Anthropic AI only: use the Message Batches API")
	output := fs.String("o", "", "write the full JSON report")
	fs.StringVar(output, "output", "", "write the full JSON report")
	html := fs.String("html", "", "write the self-contained HTML report")
	limit := fs.Int("limit", 0, "report the top N after deterministic SSVC screening")
	files, err := parseInterleaved(fs, args)
	if err != nil {
		return runConfig{}, err
	}
	if *triage == "" {
		*triage, _ = ai.LoadConfig()["default_backend"].(string)
	}
	switch *triage {
	case "":
		*triage = "rules"
	case "rules", "ai", "claude", "cascade":
	default:
		return runConfig{}, fmt.Errorf("Unknown triage backend: %s", *triage)
	}
	if len(files) == 0 {
		return runConfig{}, errors.New("run needs at least one scanner JSON or SBOM file")
	}
	tri := func(yes, no bool) *bool {
		switch {
		case yes:
			return &yes
		case no:
			v := false
			return &v
		}
		return nil
	}
	cfg := runConfig{files: files, output: *output, html: *html, options: pipeline.Options{
		Format: *format, Inventory: *assets, ProviderStatus: "provider_reported", Limit: *limit,
		Triage: pipeline.TriageOptions{Backend: *triage, Model: *modelName, EscalationModel: *escalationModel,
			Provider: *provider, BaseURL: *aiBaseURL, Jobs: *jobs, Batch: *batch},
		Enrich: enrich.Options{UseNVD: !*noNVD, NVDAPIKey: *nvdKey, VendorSources: *vendorSources,
			GitHubToken: *githubToken, UseVulnrichment: !*noVulnrichment},
	}}
	if *noVendor {
		cfg.options.Enrich.VendorSources = ""
	}
	asset := model.NewAsset(*assetID)
	asset.Kind, asset.Criticality = "host", *criticality
	asset.InternetExposed, asset.Reachable, asset.RuntimeObserved = tri(*exposed, *notExposed), tri(*reachable, *notReachable), tri(*runtime, *notRuntime)
	override := *assetID != "" || *criticality != "unknown" || asset.InternetExposed != nil || asset.Reachable != nil || asset.RuntimeObserved != nil
	targets := map[string]*string{"system_exposure": &asset.SystemExposure, "automatable": &asset.Automatable,
		"mission_impact": &asset.MissionImpact, "safety_impact": &asset.SafetyImpact,
		"bod2604_applicability": &asset.BOD2604Applicability, "publicly_exposed": &asset.PubliclyExposed}
	for field, value := range choices {
		normalized, err := model.NormalizeChoice(field, *value)
		if err != nil {
			return runConfig{}, err
		}
		*targets[field] = normalized
		override = override || normalized != "unknown"
	}
	if override {
		cfg.options.Asset = &asset
	}
	return cfg, nil
}

func execute(ctx context.Context, cfg runConfig, stdout io.Writer) (*pipeline.Assessment, error) {
	cfg.options.Progress = func(msg string) { fmt.Fprintln(stdout, msg) }
	result, err := assess(ctx, cfg.files, cfg.options)
	if err != nil {
		return nil, err
	}
	escalated, fellBack := 0, 0
	for _, f := range result.Subset {
		if f.Triage != nil && f.Triage.Escalated != nil && *f.Triage.Escalated {
			escalated++
		}
		if f.Triage != nil && f.Triage.Backend == "rules_fallback" {
			fellBack++
		}
	}
	if cfg.options.Triage.Backend == "cascade" {
		fmt.Fprintf(stdout, "cascade: %d/%d findings escalated to the frontier model\n", escalated, len(result.Subset))
	}
	if fellBack > 0 {
		fmt.Fprintf(stdout, "%d findings fell back to the rules baseline after API errors (tagged in the report)\n", fellBack)
	}
	return result, emit(result, cfg.output, cfg.html, cfg.warnings, stdout)
}

// emit prints the action queue and writes the requested reports.
func emit(result *pipeline.Assessment, output, html string, warnings []string, stdout io.Writer) error {
	fmt.Fprintln(stdout, "\nRemediation actions (SSVC deployment outcome first)")
	for i, a := range result.Actions {
		if i == 20 {
			fmt.Fprintf(stdout, "  … %d more actions in the report\n", len(result.Actions)-20)
			break
		}
		effective := "—"
		if a.EffectiveDeadlineDays != nil {
			effective = fmt.Sprintf("%dd (%s)", *a.EffectiveDeadlineDays, a.EffectiveRule)
		}
		bod := "—"
		if label, ok := a.BOD2604["label"].(string); ok {
			bod = label
		}
		fmt.Fprintf(stdout, "  %2d. %-12s %s  [%d CVE, workflow %dd, BOD %s, effective %s]\n", i+1,
			pipeline.PriorityDefinition(a.TopPriority)["ssvc_outcome"], a.Summary, len(a.CVEs), a.DeadlineDays, bod, effective)
	}
	audit := result.Audit
	if len(audit.Flagged) > 0 {
		fmt.Fprintf(stdout, "audit: %d/%d decisions verified; %d flagged for human review\n", audit.Verified, audit.Total, len(audit.Flagged))
	} else {
		fmt.Fprintf(stdout, "audit: %d/%d decisions verified against deterministic signals\n", audit.Verified, audit.Total)
	}
	printEval(stdout, result.EvalRows)
	printDecisionQuality(stdout, pipeline.DecisionQuality(result.Subset))
	status, _ := result.Coverage["status"].(string)
	if msg := pipeline.ResultMessage(len(result.Findings), len(result.Actions), result.Coverage["complete"] != true, status, result.Coverage); msg != "" {
		fmt.Fprintln(stdout, msg)
	}
	if html != "" {
		if err := report.WriteHTML(html, result.Subset, result.Actions, result.EvalRows, report.HTMLOptions{Coverage: result.Coverage, CoverageWarnings: warnings}); err != nil {
			return err
		}
		fmt.Fprintln(stdout, "HTML report:", outputLocation(html))
	}
	if output != "" {
		if err := report.WriteJSON(output, result); err != nil {
			return err
		}
		fmt.Fprintln(stdout, "JSON report:", outputLocation(output))
	}
	return nil
}

// printEval compares the queue each ranking would build: how many target
// findings land within the top k.
func printEval(stdout io.Writer, rows []pipeline.EvalRow) {
	const row = "  %-8s %-9s %-9s %-9s %-9s   %-11s %-11s %-11s %-11s\n"
	fmt.Fprintln(stdout, "\nOutcome check: CVSS vs EPSS vs KEV-first vs SSVC (* = best)")
	fmt.Fprintf(stdout, row, "Budget", "KEV CVSS", "KEV EPSS", "KEV first", "KEV SSVC",
		"Urgent CVSS", "Urgent EPSS", "Urgent KEV", "Urgent SSVC")
	cells := func(total int, values ...int) []any {
		best := slices.Max(values)
		var out []any
		for _, v := range values {
			cell := fmt.Sprintf("%d/%d", v, total)
			if v == best {
				cell += "*"
			}
			out = append(out, cell)
		}
		return out
	}
	for _, r := range rows {
		args := append([]any{fmt.Sprintf("top %d", r.K)}, cells(r.KEVTotal, r.KEVBaseline, r.KEVEPSS, r.KEVKEV, r.KEVSSVC)...)
		fmt.Fprintf(stdout, row, append(args, cells(r.UrgentTotal, r.UrgentCVSS, r.UrgentEPSS, r.UrgentKEV, r.UrgentSSVC)...)...)
	}
	fmt.Fprintln(stdout, "How to read x/y: x target findings appear within that top-k queue, out of y target findings "+
		"in the full result. KEV = CISA Known Exploited Vulnerabilities; Urgent = SSVC Immediate or Out-of-Cycle "+
		"(P1/P2). Example: 1/2 at top 1 means the first-ranked item captures one of the two target findings.")
}

// printDecisionQuality says plainly how much of a run rests on authority
// versus assumption.
func printDecisionQuality(stdout io.Writer, q map[string]any) {
	if q["points_total"] == 0 {
		return
	}
	fmt.Fprintf(stdout, "\nDecision quality: %v/%v vulnerability-specific inputs (%.1f%%) came from a published or "+
		"analyst-confirmed source; %v used SSVC's conservative default.\n",
		q["authoritative"], q["points_total"], q["authoritative_pct"].(float64), q["assumed"])
	if n, _ := q["de_escalated"].(int); n > 0 {
		fmt.Fprintf(stdout, "  %d finding(s) were de-escalated by a published CISA assessment (they would otherwise "+
			"have been over-prioritized).\n", n)
	}
	if n, _ := q["needs_confirmation"].(int); n > 0 {
		fmt.Fprintf(stdout, "  %d finding(s) need analyst confirmation.\n", n)
	}
}

// demo runs the bundled scanner outputs against an isolated cache seeded
// with the bundled EPSS/KEV/NVD/Vulnrichment snapshots: no network, no keys.
func demo(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	html := fs.String("html", "demo_report.html", "HTML output path")
	output := fs.String("o", "demo_report.json", "JSON output path")
	fs.StringVar(output, "output", "demo_report.json", "JSON output path")
	if _, err := parseInterleaved(fs, args); err != nil {
		return err
	}
	work, err := os.MkdirTemp("", "patchtriage-demo-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	cache := filepath.Join(work, "cache")
	if err := enrich.SeedDemoCache(cache); err != nil {
		return err
	}
	var files []string
	for _, name := range []string{"fixtures/trivy_sample.json", "fixtures/grype_sample.json", "demo_assets.yaml"} {
		raw, err := data.ReadFile(name)
		if err != nil {
			return err
		}
		path := filepath.Join(work, filepath.Base(name))
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			return err
		}
		files = append(files, path)
	}
	fmt.Fprintln(stdout, "using isolated offline enrichment snapshot in", cache)
	result, err := pipeline.Assess(ctx, files[:2], pipeline.Options{
		Inventory: files[2], ProviderStatus: "complete",
		Enrich:   enrich.Options{UseNVD: true, UseVulnrichment: true, CacheDir: cache},
		Progress: func(msg string) { fmt.Fprintln(stdout, msg) },
	})
	if err != nil {
		return err
	}
	if err := emit(result, *output, *html, nil, stdout); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "\nDemo complete. Open %s in a browser.\n", strings.TrimSpace(*html))
	return nil
}

// verify runs the offline conformance and reproducibility proof.
func verify(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	output := fs.String("output", "verification_report.json", "write the reviewer-readable JSON evidence report")
	repeats := fs.Int("repeats", 25, "repeat each fixed target-context decision this many times (2-1000)")
	if _, err := parseInterleaved(fs, args); err != nil {
		return err
	}
	if *repeats < 2 || *repeats > 1000 {
		return fmt.Errorf("--repeats must be between 2 and 1000")
	}
	result, err := validation.WriteReport(*output, *repeats)
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, "Reviewer verification")
	for _, c := range result["checks"].([]map[string]any) {
		status := "PASS"
		if c["passed"] != true {
			status = "FAIL"
		}
		fmt.Fprintf(stdout, "  %-40s %6v  %s\n", strings.ReplaceAll(c["name"].(string), "_", " "), c["cases"], status)
	}
	fmt.Fprintln(stdout, "Input fingerprint:", result["input_fingerprint"])
	fmt.Fprintln(stdout, "Decision fingerprint:", result["decision_fingerprint"])
	fmt.Fprintln(stdout, "JSON evidence:", *output)
	if result["status"] != "pass" {
		return errors.New("verification failed")
	}
	return nil
}

// serve starts the GUI. It binds to localhost unless told otherwise.
func serve(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	host := fs.String("host", "127.0.0.1", "bind address")
	port := fs.Int("port", 8765, "TCP port")
	noBrowser := fs.Bool("no-browser", false, "do not open a browser")
	if _, err := parseInterleaved(fs, args); err != nil {
		return err
	}
	if *port < 1 || *port > 65535 {
		return fmt.Errorf("--port must be between 1 and 65535")
	}
	store := &web.Store{Root: web.DefaultConfigDir()}
	runner := &web.Runner{Store: store, Enrich: enrich.Options{UseNVD: true, NVDAPIKey: os.Getenv("NVD_API_KEY"),
		VendorSources: "auto", UseVulnrichment: true}}
	return web.Serve(ctx, *host, *port, !*noBrowser, runner)
}

// fleetGitHub is the GitHub client fleet uses; tests point it at a fake.
var fleetGitHub repository.GitHub

// fleet imports a GitHub account's repositories as targets of the local
// store, assesses each with the deterministic engine and writes one
// cross-target rollup.
func fleet(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("fleet", flag.ContinueOnError)
	limit := fs.Int("limit", 10, "repositories to import, most recently pushed first (1-100)")
	includeForks := fs.Bool("include-forks", false, "also import forked repositories")
	includeArchived := fs.Bool("include-archived", false, "also import archived repositories")
	noAssess := fs.Bool("no-assess", false, "import targets only; run assessments later (GUI or rerun)")
	triage := fs.String("triage", "rules", "triage backend for the per-target assessments: rules|ai|cascade")
	shared := map[string]*string{
		"system_exposure": fs.String("ssvc-exposure", "unknown", "shared SSVC System Exposure for every imported target"),
		"mission_impact":  fs.String("ssvc-mission-impact", "unknown", "shared SSVC Mission Impact for every imported target"),
		"safety_impact":   fs.String("ssvc-safety-impact", "unknown", "shared SSVC Safety Impact for every imported target"),
	}
	token := fs.String("github-token", os.Getenv("GITHUB_TOKEN"), "optional token (rate limits)")
	output := fs.String("o", "", "write the fleet rollup as JSON")
	fs.StringVar(output, "output", "", "write the fleet rollup as JSON")
	html := fs.String("html", "fleet_report.html", "write the fleet HTML report")
	noNVD := fs.Bool("no-nvd", false, "skip NVD during assessment (faster)")
	positional, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return errors.New("fleet takes one GitHub account URL, e.g. https://github.com/your-org")
	}
	if *limit < 1 || *limit > 100 {
		return errors.New("--limit must be between 1 and 100")
	}
	switch *triage {
	case "rules", "ai", "claude", "cascade":
	default:
		return fmt.Errorf("Unknown triage backend: %s", *triage)
	}
	sharedContext := map[string]string{}
	for field, value := range shared {
		normalized, err := model.NormalizeChoice(field, *value)
		if err != nil {
			return err
		}
		sharedContext[field] = normalized
	}
	store := &web.Store{Root: web.DefaultConfigDir()}
	fmt.Fprintf(stdout, "listing and importing repositories from %s...\n", positional[0])
	imported, err := web.FleetImport{Store: store, GitHub: fleetGitHub, Token: *token}.Import(ctx, "", positional[0], *limit,
		*includeForks, *includeArchived, sharedContext)
	if err != nil {
		return err
	}
	owner, _ := imported["owner"].(string)
	fmt.Fprintf(stdout, "\nFleet import - %s\n", owner)
	var ids []string
	for _, row := range imported["results"].([]map[string]any) {
		status, _ := row["status"].(string)
		detail := fmt.Sprint(row["error"])
		if row["error"] == nil {
			detail = ""
		}
		if status == "imported" {
			detail = fmt.Sprintf("%v components (%v)", row["component_count"], row["coverage_status"])
		}
		fmt.Fprintf(stdout, "  %-40s %-17s %s\n", row["repository"], status, truncate(detail, 80))
		if id, ok := row["target_id"].(string); ok && id != "" {
			ids = append(ids, id)
		}
	}
	listing := imported["listing"].(map[string]any)
	if forks, archived := listing["skipped_forks"].(int), listing["skipped_archived"].(int); forks+archived > 0 {
		fmt.Fprintf(stdout, "skipped %d fork(s) and %d archived; use --include-forks / --include-archived to import them\n",
			forks, archived)
	}
	if warnings, ok := listing["warnings"].([]string); ok {
		for _, w := range warnings {
			fmt.Fprintln(stdout, "note:", w)
		}
	}
	if stopped, _ := imported["stopped_reason"].(string); stopped != "" {
		fmt.Fprintln(stdout, "stopped:", stopped)
	}
	if len(ids) == 0 {
		return errors.New("no targets were imported; nothing to assess")
	}
	if !*noAssess {
		runner := &web.Runner{Store: store, Enrich: enrich.Options{UseNVD: !*noNVD, NVDAPIKey: os.Getenv("NVD_API_KEY"),
			VendorSources: "auto", UseVulnrichment: true}}
		failures := 0
		for i, id := range ids {
			target, err := store.Get("", id)
			if err != nil {
				continue
			}
			label := fmt.Sprintf("[%d/%d] %v", i+1, len(ids), target["name"])
			fmt.Fprintf(stdout, "assessing %s...\n", label)
			summary, err := runner.Run(ctx, "", target, *triage)
			if err != nil {
				failures++
				fmt.Fprintf(stdout, "%s: assessment failed - %v\n", label, err)
				continue
			}
			outcomes, _ := summary["outcomes"].(map[string]any)
			fmt.Fprintf(stdout, "%s: %v finding(s) - immediate %v, out-of-cycle %v\n", label, summary["total"],
				orZero(outcomes["immediate"]), orZero(outcomes["out_of_cycle"]))
		}
		if failures > 0 {
			fmt.Fprintf(stdout, "%d target(s) failed assessment; they are listed as not assessed in the fleet report\n", failures)
		}
	}
	rollup, err := web.AggregateFleet(store, "", ids)
	if err != nil {
		return err
	}
	outcomes := rollup["outcomes"].(map[string]int)
	fmt.Fprintf(stdout, "\nFleet: %v/%v targets assessed - %d immediate, %d out-of-cycle, %d scheduled, %d defer - %v on CISA KEV\n",
		rollup["targets_assessed"], rollup["targets_total"], outcomes["immediate"], outcomes["out_of_cycle"],
		outcomes["scheduled"], outcomes["defer"], rollup["kev_total"])
	if queue := rollup["queue"].([]map[string]any); len(queue) > 0 {
		fmt.Fprintln(stdout, "Cross-target action queue (top 10)")
		for _, entry := range queue[:min(10, len(queue))] {
			kev := fmt.Sprint(orZero(entry["kev_count"]))
			if kev == "0" {
				kev = "-"
			}
			days := orZero(entry["deadline_days"])
			if fmt.Sprint(days) == "0" {
				days = 90
			}
			fmt.Fprintf(stdout, "  %-12v %-30v %-60s KEV %-3s %vd\n", entry["outcome_label"], entry["target_name"],
				truncate(fmt.Sprint(entry["summary"]), 60), kev, days)
		}
	}
	if err := report.WriteFleetHTML(*html, rollup, "PatchTriage - Fleet Report - "+owner); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "fleet HTML report:", outputLocation(*html))
	if *output != "" {
		raw, err := json.MarshalIndent(map[string]any{"import": imported, "rollup": rollup}, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(*output, raw, 0o644); err != nil {
			return err
		}
		fmt.Fprintln(stdout, "fleet JSON rollup:", outputLocation(*output))
	}
	return nil
}

func orZero(v any) any {
	if v == nil {
		return 0
	}
	return v
}

func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}
