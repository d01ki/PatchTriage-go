// Command patchtriage turns scanner evidence into SSVC patch deployment
// decisions: run (scriptable pipeline), demo (offline demonstration),
// verify (conformance proof) and serve (GUI).
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
	"github.com/d01ki/PatchTriage-go/internal/enrich"
	"github.com/d01ki/PatchTriage-go/internal/model"
	"github.com/d01ki/PatchTriage-go/internal/pipeline"
	"github.com/d01ki/PatchTriage-go/internal/report"
)

const usage = `usage: patchtriage <command> [options]

commands:
  run FILES...   scanner JSON (Trivy/Grype/OSV) or CycloneDX/SPDX SBOM -> decisions and reports
  demo           fully offline demo with bundled evidence
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(stderr, usage)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	var err error
	switch args[0] {
	case "run":
		var cfg runConfig
		if cfg, err = parseRun(args[1:]); err == nil {
			err = execute(ctx, cfg, stdout)
		}
	case "demo":
		err = demo(ctx, args[1:], stdout)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n%s", args[0], usage)
		return 2
	}
	if err != nil {
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
}

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
	triage := fs.String("triage", "rules", "triage backend (this Go port supports rules)")
	output := fs.String("o", "", "write the full JSON report")
	fs.StringVar(output, "output", "", "write the full JSON report")
	html := fs.String("html", "", "write the self-contained HTML report")
	limit := fs.Int("limit", 0, "report the top N after deterministic SSVC screening")
	files, err := parseInterleaved(fs, args)
	if err != nil {
		return runConfig{}, err
	}
	if *triage != "rules" {
		return runConfig{}, fmt.Errorf("triage backend %q is not available: this Go port supports only the deterministic 'rules' backend", *triage)
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

func execute(ctx context.Context, cfg runConfig, stdout io.Writer) error {
	cfg.options.Progress = func(msg string) { fmt.Fprintln(stdout, msg) }
	result, err := pipeline.Assess(ctx, cfg.files, cfg.options)
	if err != nil {
		return err
	}
	return emit(result, cfg.output, cfg.html, stdout)
}

// emit prints the action queue and writes the requested reports.
func emit(result *pipeline.Assessment, output, html string, stdout io.Writer) error {
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
		if err := report.WriteHTML(html, result.Subset, result.Actions, result.EvalRows, report.HTMLOptions{Coverage: result.Coverage}); err != nil {
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
	if err := emit(result, *output, *html, stdout); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "\nDemo complete. Open %s in a browser.\n", strings.TrimSpace(*html))
	return nil
}
