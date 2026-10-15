// Command patchtriage turns scanner evidence into SSVC patch deployment
// decisions: run (scriptable pipeline), demo (offline demonstration),
// verify (conformance proof), serve (GUI), and the guided setup, start and
// remediate workflows.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"github.com/d01ki/PatchTriage-go/data"
	"github.com/d01ki/PatchTriage-go/internal/ai"
	"github.com/d01ki/PatchTriage-go/internal/enrich"
	"github.com/d01ki/PatchTriage-go/internal/model"
	"github.com/d01ki/PatchTriage-go/internal/pipeline"
	"github.com/d01ki/PatchTriage-go/internal/report"
	"github.com/d01ki/PatchTriage-go/internal/validation"
	"github.com/d01ki/PatchTriage-go/internal/web"
)

const usage = `usage: patchtriage <command> [options]

commands:
  run FILES...   scanner JSON (Trivy/Grype/OSV) or CycloneDX/SPDX SBOM -> decisions and reports
  demo           fully offline demo with bundled evidence
  verify         offline SSVC conformance and reproducibility proof
  serve          GUI console (default http://127.0.0.1:8765)
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
	q := pipeline.DecisionQuality(result.Subset)
	if q["points_total"] != 0 {
		fmt.Fprintf(stdout, "decision quality: %v of %v vulnerability-specific inputs authoritative (%.1f%%); %v finding(s) need confirmation\n",
			q["authoritative"], q["points_total"], q["authoritative_pct"], q["needs_confirmation"])
	}
	status, _ := result.Coverage["status"].(string)
	if msg := pipeline.ResultMessage(len(result.Findings), len(result.Actions), result.Coverage["complete"] != true, status, result.Coverage); msg != "" {
		fmt.Fprintln(stdout, msg)
	}
	if html != "" {
		if err := report.WriteHTML(html, result.Subset, result.Actions, result.EvalRows, report.HTMLOptions{Coverage: result.Coverage, CoverageWarnings: warnings}); err != nil {
			return err
		}
		fmt.Fprintln(stdout, "HTML report:", html)
	}
	if output != "" {
		if err := report.WriteJSON(output, result); err != nil {
			return err
		}
		fmt.Fprintln(stdout, "JSON report:", output)
	}
	return nil
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
