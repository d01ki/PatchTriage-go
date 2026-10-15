package main

// Interactive commands: the setup wizard, the guided start run and guided
// local remediation, with the prompts they share.

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/d01ki/PatchTriage-go/internal/ai"
	"github.com/d01ki/PatchTriage-go/internal/enrich"
	"github.com/d01ki/PatchTriage-go/internal/model"
	"github.com/d01ki/PatchTriage-go/internal/pipeline"
	"github.com/d01ki/PatchTriage-go/internal/remediation"
	"github.com/d01ki/PatchTriage-go/internal/repository"
	"github.com/d01ki/PatchTriage-go/internal/web"
)

// stdin feeds every prompt; tests replace it.
var stdin io.Reader = os.Stdin

// exitCode makes run return a specific process status.
type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

var errAborted = errors.New("Aborted!")

// prompter asks questions like typer.prompt / typer.confirm: an empty
// answer takes the default.
type prompter struct {
	in  *bufio.Reader
	out io.Writer
}

func newPrompter(out io.Writer) *prompter { return &prompter{in: bufio.NewReader(stdin), out: out} }

func (p *prompter) line() (string, error) {
	text, err := p.in.ReadString('\n')
	if err != nil && text == "" {
		return "", errAborted
	}
	return strings.TrimRight(text, "\r\n"), nil
}

// ask prompts for text; showDefault prints the default in brackets.
func (p *prompter) ask(label, def string, showDefault bool) (string, error) {
	if showDefault && def != "" {
		fmt.Fprintf(p.out, "%s [%s]: ", label, def)
	} else {
		fmt.Fprintf(p.out, "%s: ", label)
	}
	answer, err := p.line()
	if err != nil {
		return "", err
	}
	if answer == "" {
		return def, nil
	}
	return answer, nil
}

// secret prompts without echo on a real terminal; piped input stays
// visible (as in the Python CLI) so scripted runs never hang.
func (p *prompter) secret(label string) (string, error) {
	file, ok := stdin.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return p.ask(label, "", false)
	}
	fmt.Fprintf(p.out, "%s: ", label)
	raw, err := term.ReadPassword(int(file.Fd()))
	fmt.Fprintln(p.out)
	if err != nil {
		return "", errAborted
	}
	return string(raw), nil
}

// choice prompts until the lower-cased answer is one of choices.
func (p *prompter) choice(label string, choices []string, def string) (string, error) {
	for {
		value, err := p.ask(label, def, true)
		if err != nil {
			return "", err
		}
		value = strings.ToLower(strings.TrimSpace(value))
		if slices.Contains(choices, value) {
			return value, nil
		}
		fmt.Fprintf(p.out, "pick one of %s\n", strings.Join(choices, ", "))
	}
}

func (p *prompter) confirm(label string, def bool) (bool, error) {
	hint := "[y/N]"
	if def {
		hint = "[Y/n]"
	}
	for {
		fmt.Fprintf(p.out, "%s %s: ", label, hint)
		answer, err := p.line()
		if err != nil {
			return false, err
		}
		switch strings.ToLower(strings.TrimSpace(answer)) {
		case "":
			return def, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		}
		fmt.Fprintln(p.out, "Error: invalid input")
	}
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func isFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func expandHome(path string) string {
	if path == "~" || strings.HasPrefix(path, "~/") || strings.HasPrefix(path, `~\`) {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[1:])
		}
	}
	return path
}

// existingPath prompts until the operator names an existing file or directory.
func (p *prompter) existingPath(label, def string, directory bool) (string, error) {
	expected := "file"
	if directory {
		expected = "directory"
	}
	for {
		value, err := p.ask(label, def, true)
		if err != nil {
			return "", err
		}
		path := expandHome(strings.TrimSpace(value))
		if directory && isDir(path) || !directory && isFile(path) {
			return path, nil
		}
		fmt.Fprintf(p.out, "%s is not an existing %s\n", path, expected)
	}
}

func defaultRemediationOutput(repository string) string {
	abs, _ := filepath.Abs(repository)
	return filepath.Join(filepath.Dir(abs), filepath.Base(abs)+"-patchtriage-remediation")
}

func withinDir(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func (p *prompter) remediationOutput(repository string) (string, error) {
	repoAbs, _ := filepath.Abs(repository)
	for {
		value, err := p.ask("Output directory", defaultRemediationOutput(repository), true)
		if err != nil {
			return "", err
		}
		output, _ := filepath.Abs(expandHome(strings.TrimSpace(value)))
		if withinDir(output, repoAbs) {
			fmt.Fprintln(p.out, "output must be outside the source repository")
			continue
		}
		if info, err := os.Stat(output); err == nil {
			entries, _ := os.ReadDir(output)
			if !info.IsDir() || len(entries) > 0 {
				fmt.Fprintln(p.out, "output must be absent or an empty directory")
				continue
			}
		}
		return output, nil
	}
}

func (p *prompter) upgradeAction(report string) (string, error) {
	actions, err := remediation.LoadUpgradeActions(report)
	if err != nil {
		return "", err
	}
	if len(actions) == 0 {
		return "", errors.New("the report contains no confirmed upgrade action")
	}
	fmt.Fprintln(p.out, "Confirmed dependency upgrades")
	for i, a := range actions {
		installed := a.InstalledVersion
		if installed == "" {
			installed = "?"
		}
		fmt.Fprintf(p.out, "  %2d  %-3s %s  %s -> %s  (%d CVEs)\n", i+1, a.TopPriority, a.Package, installed, a.TargetVersion, len(a.CVEs))
	}
	for {
		selected, err := p.ask("Upgrade number to patch", "1", true)
		if err != nil {
			return "", err
		}
		if index, err := strconv.Atoi(strings.TrimSpace(selected)); err == nil && index >= 1 && index <= len(actions) {
			return actions[index-1].ActionID, nil
		}
		fmt.Fprintf(p.out, "pick a number from 1 to %d\n", len(actions))
	}
}

func (p *prompter) checkCommands() ([]string, error) {
	fmt.Fprintln(p.out, "\nVerification commands - add one command at a time. Shell operators are not accepted; "+
		"enter separate commands instead.")
	fmt.Fprintln(p.out, "Examples: npm test  |  python -m pytest  |  cargo test")
	var checks []string
	for {
		value, err := p.ask("Check command (Enter when done)", "", false)
		if err != nil {
			return nil, err
		}
		if value = strings.TrimSpace(value); value == "" {
			return checks, nil
		}
		if _, err := remediation.ParseCheckCommand(value); err != nil {
			fmt.Fprintln(p.out, err)
			continue
		}
		checks = append(checks, value)
	}
}

func printRemediationResult(out io.Writer, r *remediation.Result) {
	fmt.Fprintf(out, "remediation: %s\n  action:    %s\n  workspace: %s\n  patch:     %s\n  files:     %s\n",
		r.Status, r.Action.Summary, r.Workspace, r.PatchFile, strings.Join(r.ChangedFiles, ", "))
	for _, w := range r.Warnings {
		fmt.Fprintln(out, "warning:", w)
	}
	if len(r.Scan.RemainingCVEs) > 0 {
		fmt.Fprintln(out, "remaining target CVEs:", strings.Join(r.Scan.RemainingCVEs, ", "))
	}
	fmt.Fprintln(out, "\nLocal review commands")
	for _, c := range []string{
		fmt.Sprintf(`git -C "%s" diff --check`, r.Workspace),
		fmt.Sprintf(`git -C "%s" diff`, r.Workspace),
		fmt.Sprintf(`git -C "%s" apply --check "%s"`, r.SourceRepository, r.PatchFile),
		fmt.Sprintf(`git -C "%s" apply "%s"`, r.SourceRepository, r.PatchFile),
	} {
		fmt.Fprintln(out, " ", c)
	}
}

// remediateInputs are the remediate options; empty fields are prompted
// for in the guided workflow.
type remediateInputs struct {
	report, repository, outputDir, actionID, scanner string
	checks                                           []string
	checksGiven, noLock, noScan                      bool
	timeout                                          time.Duration
}

// guidedRemediation collects missing inputs and executes the patch.
func guidedRemediation(in remediateInputs, out io.Writer) error {
	return guidedRemediationWith(newPrompter(out), in)
}

// guidedRemediationWith reuses the caller's prompter: one buffered reader
// over stdin, so no typed-ahead answer is lost between workflows.
func guidedRemediationWith(p *prompter, in remediateInputs) error {
	out := p.out
	guided := in.report == "" || in.repository == ""
	fmt.Fprintln(out, "\nLocal dependency remediation - the source checkout stays unchanged; PatchTriage works in an isolated Git clone.")
	var err error
	if in.report == "" {
		if in.report, err = p.existingPath("PatchTriage JSON report", "report.json", false); err != nil {
			return err
		}
	} else if !isFile(in.report) {
		return fmt.Errorf("%s is not an existing file", in.report)
	}
	if in.repository == "" {
		if in.repository, err = p.existingPath("Local Git repository", ".", true); err != nil {
			return err
		}
	} else if !isDir(in.repository) {
		return fmt.Errorf("%s is not an existing directory", in.repository)
	}
	if _, err := os.Stat(filepath.Join(in.repository, ".git")); err != nil {
		return fmt.Errorf("%s is not a Git working tree", in.repository)
	}
	if guided && in.actionID == "" {
		if in.actionID, err = p.upgradeAction(in.report); err != nil {
			return err
		}
	}
	if guided && !in.checksGiven {
		if in.checks, err = p.checkCommands(); err != nil {
			return err
		}
	}
	if in.outputDir == "" {
		in.outputDir = defaultRemediationOutput(in.repository)
		if guided {
			if in.outputDir, err = p.remediationOutput(in.repository); err != nil {
				return err
			}
		}
	}
	refresh, rescan := !in.noLock, !in.noScan
	if guided && !in.noLock {
		if refresh, err = p.confirm("Refresh a supported lockfile?", true); err != nil {
			return err
		}
	}
	if guided && !in.noScan {
		if rescan, err = p.confirm("Rescan the isolated patch with OSV-Scanner when available?", true); err != nil {
			return err
		}
	}
	if guided {
		checks := "none"
		if len(in.checks) > 0 {
			checks = strings.Join(in.checks, ", ")
		}
		fmt.Fprintf(out, "\nExecution plan\n  report:     %s\n  repository: %s\n  output:     %s\n  checks:     %s\n",
			in.report, in.repository, in.outputDir, checks)
		ok, err := p.confirm("Create and verify this patch?", true)
		if err != nil {
			return err
		}
		if !ok {
			fmt.Fprintln(out, "remediation cancelled")
			return nil
		}
	}
	result, err := remediation.Execute(in.report, in.repository, in.outputDir, remediation.Options{ActionID: in.actionID,
		Checks: in.checks, RefreshLockfiles: refresh, Rescan: rescan, Scanner: in.scanner, Timeout: in.timeout})
	if err != nil {
		return err
	}
	printRemediationResult(out, result)
	if result.Status == "verification_failed" {
		return exitCode(2)
	}
	return nil
}

// repeated collects a repeatable string flag.
type repeated []string

func (r *repeated) String() string     { return strings.Join(*r, ",") }
func (r *repeated) Set(v string) error { *r = append(*r, v); return nil }

func remediate(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("remediate", flag.ContinueOnError)
	var in remediateInputs
	fs.StringVar(&in.repository, "repository", "", "local Git working tree; omit to be prompted")
	fs.StringVar(&in.repository, "r", "", "shorthand for --repository")
	fs.StringVar(&in.outputDir, "output-dir", "", "empty/absent directory for the isolated workspace and artifacts")
	fs.StringVar(&in.outputDir, "o", "", "shorthand for --output-dir")
	fs.StringVar(&in.actionID, "action-id", "", "upgrade action to apply (default: highest-priority upgrade)")
	var checks repeated
	fs.Var(&checks, "check", "verification command; repeat for multiple commands")
	fs.BoolVar(&in.noLock, "no-lock", false, "do not refresh a detected supported lockfile")
	fs.BoolVar(&in.noScan, "no-scan", false, "do not rescan the patched workspace")
	fs.StringVar(&in.scanner, "scanner", "", "OSV-Scanner executable path (auto-detected by default)")
	timeout := fs.Int("timeout", 600, "per-command timeout in seconds")
	positional, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if len(positional) > 1 {
		return errors.New("remediate takes at most one REPORT")
	}
	if len(positional) == 1 {
		in.report = positional[0]
	}
	if *timeout < 1 {
		return errors.New("--timeout must be at least 1")
	}
	in.timeout = time.Duration(*timeout) * time.Second
	fs.Visit(func(f *flag.Flag) { in.checksGiven = in.checksGiven || f.Name == "check" })
	in.checks = checks
	if err := guidedRemediation(in, stdout); err != nil {
		var code exitCode
		if errors.As(err, &code) {
			return err
		}
		return fmt.Errorf("remediation failed: %w", err)
	}
	return nil
}

// ------------------------------------------------------------ setup

// validateKey checks an API key against the provider's models endpoint;
// tests replace it.
var validateKey = func(ctx context.Context, provider, key string) (bool, string) {
	endpoint := ai.AnthropicModelsURL
	if provider == "openai" {
		endpoint = ai.OpenAIModelsURL
	}
	return ai.ValidateKey(ctx, http.DefaultClient, provider, endpoint, key)
}

func savedString(cfg map[string]any, key string) string {
	value, _ := cfg[key].(string)
	return value
}

func withCurrent(label, current string) string {
	if current != "" {
		return fmt.Sprintf("%s [current: %s]", label, ai.Mask(current))
	}
	return label
}

// validatedKey asks for a provider key until it validates, the operator
// gives up, or nothing is entered; it reports whether AI stays enabled.
func (p *prompter) validatedKey(ctx context.Context, cfg map[string]any, provider, configKey, label, service string) (bool, error) {
	current := savedString(cfg, configKey)
	for {
		key, err := p.secret(withCurrent(label, current))
		if err != nil {
			return false, err
		}
		if key = strings.TrimSpace(key); key == "" {
			key = current
		}
		if key == "" {
			fmt.Fprintln(p.out, "no key saved; using deterministic rules")
			return false, nil
		}
		fmt.Fprintf(p.out, "validating key against the %s API...\n", service)
		ok, msg := validateKey(ctx, provider, key)
		if ok {
			fmt.Fprintln(p.out, "OK:", msg)
			cfg[configKey] = key
			return true, nil
		}
		fmt.Fprintln(p.out, msg)
		again, err := p.confirm("Try again?", true)
		if err != nil {
			return false, err
		}
		if !again {
			return current != "", nil
		}
	}
}

func setup(ctx context.Context, stdout io.Writer) error { return newPrompter(stdout).setup(ctx) }

// setup is the first-run wizard: optional AI provider and key (validated
// live), optional NVD and GitHub tokens, and the default backend. Provider
// credentials stay separate so switching providers never silently sends
// evidence to another service.
func (p *prompter) setup(ctx context.Context) error {
	cfg := ai.LoadConfig()
	fmt.Fprintln(p.out, "\nPatchTriage setup - press Enter to skip or keep the current value.")
	fmt.Fprintln(p.out)
	current := strings.ToLower(savedString(cfg, "PATCHTRIAGE_AI_PROVIDER"))
	if current == "" {
		switch {
		case savedString(cfg, "ANTHROPIC_API_KEY") != "":
			current = "anthropic"
		case savedString(cfg, "OPENAI_API_KEY") != "":
			current = "openai"
		default:
			current = "rules"
		}
	}
	providers := []string{"rules", "anthropic", "openai", "openai-compatible", "ollama"}
	provider, err := p.choice("AI provider ["+strings.Join(providers, ", ")+"]", providers, current)
	if err != nil {
		return err
	}
	hasAI := provider != "rules"
	switch provider {
	case "anthropic":
		hasAI, err = p.validatedKey(ctx, cfg, provider, "ANTHROPIC_API_KEY", "Anthropic API key (sk-ant-...)", "Anthropic")
	case "openai":
		hasAI, err = p.validatedKey(ctx, cfg, provider, "OPENAI_API_KEY", "OpenAI API key", "OpenAI")
	case "openai-compatible", "ollama":
		err = p.compatibleProvider(cfg, provider, &hasAI)
	}
	if err != nil {
		return err
	}
	if hasAI && provider != "anthropic" {
		modelID, err := p.ask("AI model id", savedString(cfg, "PATCHTRIAGE_AI_MODEL"), true)
		if err != nil {
			return err
		}
		if modelID = strings.TrimSpace(modelID); modelID != "" {
			cfg["PATCHTRIAGE_AI_MODEL"] = modelID
		} else {
			hasAI = false
			fmt.Fprintln(p.out, "no model saved; using deterministic rules")
		}
	}
	if hasAI {
		cfg["PATCHTRIAGE_AI_PROVIDER"] = provider
	} else {
		delete(cfg, "PATCHTRIAGE_AI_PROVIDER")
	}
	for _, optional := range []struct{ key, label string }{
		{"NVD_API_KEY", "NVD API key (optional, faster NVD enrichment)"},
		{"GITHUB_TOKEN", "GitHub token (optional, raises GHSA advisory rate limits)"},
	} {
		value, err := p.secret(withCurrent(optional.label, savedString(cfg, optional.key)))
		if err != nil {
			return err
		}
		if value = strings.TrimSpace(value); value != "" {
			cfg[optional.key] = value
		}
	}
	backend := "rules"
	if hasAI {
		def := savedString(cfg, "default_backend")
		switch def {
		case "":
			def = "cascade"
		case "claude":
			def = "ai"
		}
		choices := []string{"rules", "ai", "cascade"}
		if backend, err = p.choice("Default triage backend ["+strings.Join(choices, ", ")+
			"] - cascade screens with a fast model and escalates only what matters", choices, def); err != nil {
			return err
		}
	}
	cfg["default_backend"] = backend
	path, err := ai.SaveConfig(cfg)
	if err != nil {
		return err
	}
	fmt.Fprintf(p.out, "\nSaved to %s (environment variables always take precedence)\n", path)
	fmt.Fprint(p.out, "\nNext steps:\n  patchtriage demo   offline demo, no keys needed\n"+
		"  patchtriage start  guided run on your own scans\n")
	return nil
}

// compatibleProvider asks for an OpenAI-compatible endpoint and its
// optional key; a missing base URL turns AI off.
func (p *prompter) compatibleProvider(cfg map[string]any, provider string, hasAI *bool) error {
	defaultURL := savedString(cfg, "PATCHTRIAGE_AI_BASE_URL")
	if provider == "ollama" {
		defaultURL = "http://localhost:11434/v1"
	}
	baseURL, err := p.ask("OpenAI-compatible API base URL", defaultURL, true)
	if err != nil {
		return err
	}
	if baseURL = strings.TrimSpace(baseURL); baseURL == "" {
		*hasAI = false
		fmt.Fprintln(p.out, "no base URL saved; using deterministic rules")
	} else {
		cfg["PATCHTRIAGE_AI_BASE_URL"] = baseURL
	}
	key, err := p.secret(withCurrent("Provider API key (Enter if the local endpoint needs no key)",
		savedString(cfg, "PATCHTRIAGE_AI_API_KEY")))
	if err != nil {
		return err
	}
	if key = strings.TrimSpace(key); key != "" {
		cfg["PATCHTRIAGE_AI_API_KEY"] = key
	}
	return nil
}

// ------------------------------------------------------------ start

// maxSourceBytes caps imported repository evidence like the GUI
// (PATCHTRIAGE_MAX_SOURCE_BYTES, default 16 MiB).
func maxSourceBytes() int64 {
	if n, err := strconv.ParseInt(os.Getenv("PATCHTRIAGE_MAX_SOURCE_BYTES"), 10, 64); err == nil && n > 0 {
		return n
	}
	return 16 << 20
}

func githubToken() string { return firstEnv("GITHUB_TOKEN", "GH_TOKEN") }

// acquireRepository imports a repository through the GUI's acquisition
// path; tests replace it.
var acquireRepository = func(ctx context.Context, repositoryURL string) (repository.Evidence, error) {
	return repository.Acquirer{}.Acquire(ctx, repositoryURL, githubToken(), maxSourceBytes(), repository.GenericEnabled())
}

var windowsPath = regexp.MustCompile(`^([A-Za-z]):[\\/](.*)$`)

// stripInputQuotes removes quotes commonly added when a path is pasted or
// dragged into a terminal.
func stripInputQuotes(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && value[0] == value[len(value)-1] && (value[0] == '\'' || value[0] == '"') {
		return strings.TrimSpace(value[1 : len(value)-1])
	}
	return value
}

func isRepositoryURL(value string) bool {
	lower := strings.ToLower(stripInputQuotes(value))
	return strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "http://")
}

func inContainer() bool {
	_, err := os.Stat("/.dockerenv")
	return err == nil || os.Getenv("PATCHTRIAGE_IN_CONTAINER") == "1"
}

func runningUnderWSL() bool {
	if os.Getenv("WSL_DISTRO_NAME") != "" {
		return true
	}
	_, err := os.Stat("/proc/sys/fs/binfmt_misc/WSLInterop")
	return err == nil
}

// normalizeInputPattern normalizes a pasted path without hiding container
// mount boundaries: under WSL (outside a container) C:\x becomes /mnt/c/x.
func normalizeInputPattern(value string, wsl, container bool) string {
	pattern := expandHome(stripInputQuotes(value))
	if m := windowsPath.FindStringSubmatch(pattern); m != nil && wsl && !container {
		return "/mnt/" + strings.ToLower(m[1]) + "/" + strings.ReplaceAll(m[2], `\`, "/")
	}
	return pattern
}

func headless() bool {
	if inContainer() {
		return true
	}
	return runtime.GOOS == "linux" && os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == ""
}

// outputLocation shows an absolute path and, in a container, its Compose
// host destination.
func outputLocation(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	if inContainer() && withinDir(abs, "/out") {
		rel, _ := filepath.Rel("/out", abs)
		return fmt.Sprintf("%s (Docker host: ./out/%s)", abs, filepath.ToSlash(rel))
	}
	return abs
}

// offerBrowser offers to open the report, never in a headless context.
func (p *prompter) offerBrowser(html string) error {
	if headless() {
		fmt.Fprintf(p.out, "\nOpen the report: %s\n", outputLocation(html))
		if inContainer() {
			fmt.Fprintln(p.out, "(running in a container - open the file on your host via the mounted volume)")
		}
		return nil
	}
	open, err := p.confirm("Open the HTML report in your browser?", true)
	if err != nil || !open {
		return err
	}
	abs, _ := filepath.Abs(html)
	web.OpenBrowser((&url.URL{Scheme: "file", Path: "/" + strings.TrimPrefix(filepath.ToSlash(abs), "/")}).String())
	return nil
}

// startInput asks for a repository URL or scanner/SBOM files until one
// resolves. A repository yields evidence and no files.
func (p *prompter) startInput(ctx context.Context) ([]string, *repository.Evidence, error) {
	fmt.Fprintln(p.out, "\n1. Input - a repository URL, or Trivy / Grype / osv-scanner JSON, or a CycloneDX / SPDX SBOM.\n"+
		"Repository URLs are imported exactly like the web GUI: github.com through its Dependency Graph SBOM "+
		"(no clone), other HTTPS Git hosts by a static OSV-Scanner run when enabled. SBOM packages are "+
		"resolved online via OSV.dev.")
	if inContainer() {
		fmt.Fprintln(p.out, "Docker CLI: files in this repository are available under /work. "+
			"For an Explorer file picker, use the web GUI.")
	}
	for {
		entered, err := p.ask("Repository URL or file path/glob (e.g. https://github.com/owner/repo or scans/*.json)", "", false)
		if err != nil {
			return nil, nil, err
		}
		if strings.TrimSpace(entered) == "" {
			continue
		}
		if isRepositoryURL(entered) {
			repositoryURL := stripInputQuotes(entered)
			fmt.Fprintf(p.out, "importing %s ...\n", repositoryURL)
			evidence, err := acquireRepository(ctx, repositoryURL)
			var repoErr *repository.Error
			if errors.As(err, &repoErr) {
				fmt.Fprintln(p.out, repoErr.Message)
				continue
			} else if err != nil {
				return nil, nil, err
			}
			fmt.Fprintf(p.out, "imported %v (%s)\n", evidence.Provenance["repository"], evidence.Format)
			return nil, &evidence, nil
		}
		pattern := normalizeInputPattern(entered, runningUnderWSL(), inContainer())
		files, _ := filepath.Glob(pattern)
		if len(files) > 0 {
			sort.Strings(files)
			shown := strings.Join(files[:min(5, len(files))], ", ")
			if len(files) > 5 {
				shown += " ..."
			}
			fmt.Fprintf(p.out, "%d file(s): %s\n", len(files), shown)
			return files, nil, nil
		}
		fmt.Fprintf(p.out, "no files match %q\n", pattern)
		if windowsPath.MatchString(stripInputQuotes(entered)) && runtime.GOOS != "windows" {
			if inContainer() {
				fmt.Fprintln(p.out, "A container cannot see a Windows host path directly. Use the web GUI's file "+
					"picker, or copy the file into this repository and enter its /work path.")
			} else {
				fmt.Fprintln(p.out, "That looks like a Windows path, but this is not Windows. Under WSL it is "+
					"normally /mnt/<drive>/...; otherwise copy the file to this machine first.")
			}
		}
	}
}

// startContext asks for an inventory, or else the SSVC context of one
// system. The override is nil when nothing beyond "unknown" was given.
func (p *prompter) startContext() (string, *model.Asset, error) {
	fmt.Fprintln(p.out, "\n2. Asset context - the same CVE on an exposed checkout service and an internal batch box "+
		"should never rank the same.")
	inventory, err := p.ask("assets.yaml inventory (Enter to skip)", "", false)
	if inventory = strings.TrimSpace(inventory); err != nil || inventory != "" {
		return inventory, nil, err
	}
	asset := model.NewAsset("interactive")
	asset.Kind = "host"
	for _, q := range []struct {
		label   string
		choices []string
		target  *string
	}{
		{"SSVC System Exposure", []string{"open", "controlled", "small", "unknown"}, &asset.SystemExposure},
		{"SSVC Mission Impact", []string{"mission_failure", "mef_failure", "mef_support_crippled", "degraded", "unknown"}, &asset.MissionImpact},
		{"SSVC Safety Impact", []string{"catastrophic", "critical", "marginal", "negligible", "unknown"}, &asset.SafetyImpact},
	} {
		for {
			value, err := p.ask(q.label+" ["+strings.Join(q.choices, " / ")+"]", "unknown", true)
			if err != nil {
				return "", nil, err
			}
			value = strings.ReplaceAll(strings.ToLower(strings.TrimSpace(value)), "-", "_")
			if slices.Contains(q.choices, value) {
				*q.target = value
				break
			}
			fmt.Fprintf(p.out, "pick one of %s\n", strings.Join(q.choices, ", "))
		}
	}
	reachable, err := p.confirm("Is the vulnerable path confirmed reachable?", false)
	if err != nil {
		return "", nil, err
	}
	observed, err := p.confirm("Was the component/path observed at runtime?", false)
	if err != nil {
		return "", nil, err
	}
	// Only a confirmed yes is evidence; "no" stays unknown, never "unreachable".
	if reachable {
		asset.Reachable = &reachable
	}
	if observed {
		asset.RuntimeObserved = &observed
	}
	if asset.SystemExposure == "unknown" && asset.MissionImpact == "unknown" && asset.SafetyImpact == "unknown" &&
		!reachable && !observed {
		return "", nil, nil
	}
	return "", &asset, nil
}

// startBackend asks for the triage backend; ai/cascade are offered only
// with a complete AI provider configuration.
func (p *prompter) startBackend(cfg map[string]any) (string, error) {
	fmt.Fprintln(p.out, "\n3. Triage backend")
	choices := []string{"rules"}
	def := savedString(cfg, "default_backend")
	if ai.HasConfiguration() {
		choices = []string{"rules", "ai", "cascade"}
		if def == "" {
			def = "cascade"
		}
	} else {
		fmt.Fprintln(p.out, "no complete AI provider configuration - run `patchtriage setup` to enable ai/cascade")
	}
	if def == "claude" {
		def = "ai"
	}
	if !slices.Contains(choices, def) {
		def = choices[0]
	}
	return p.choice("Backend ["+strings.Join(choices, ", ")+"]", choices, def)
}

// repositoryRun points rc at the imported evidence: the repository is the
// assessed asset, and its provider coverage and warnings are carried over,
// as for a GUI target. The returned cleanup removes the evidence file.
func repositoryRun(rc *runConfig, evidence *repository.Evidence) (func(), error) {
	name, _ := evidence.Provenance["repository"].(string)
	if name == "" {
		name = "repository"
	}
	asset := model.NewAsset(name)
	if rc.options.Asset != nil {
		asset = *rc.options.Asset
	}
	asset.Identifier, asset.Kind = name, "repository"
	rc.options.Asset = &asset
	declared, _ := evidence.Provenance["coverage"].(map[string]any)
	rc.options.DeclaredCoverage = declared
	rc.options.ProviderStatus, _ = evidence.Provenance["coverage_status"].(string)
	switch warnings := evidence.Provenance["warnings"].(type) {
	case []string:
		rc.warnings = warnings
	case []any:
		for _, w := range warnings {
			rc.warnings = append(rc.warnings, fmt.Sprint(w))
		}
	}
	dir, err := os.MkdirTemp("", "patchtriage-evidence-")
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "repository."+evidence.Format+".json")
	if err := os.WriteFile(path, []byte(evidence.Content), 0o600); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	rc.files = []string{path}
	return func() { os.RemoveAll(dir) }, nil
}

// start is the guided run: input, asset context, backend, reports, and an
// optional hand-off to guided remediation.
func start(ctx context.Context, stdout io.Writer) error {
	p := newPrompter(stdout)
	if _, err := os.Stat(ai.ConfigPath()); err != nil {
		fmt.Fprintln(stdout, "No saved configuration found.")
		if first, err := p.confirm("Run setup first?", true); err != nil {
			return err
		} else if first {
			if err := p.setup(ctx); err != nil {
				return err
			}
		}
	}
	cfg := ai.LoadConfig()
	ai.ApplyToEnv(cfg)
	files, evidence, err := p.startInput(ctx)
	if err != nil {
		return err
	}
	inventory, override, err := p.startContext()
	if err != nil {
		return err
	}
	backend, err := p.startBackend(cfg)
	if err != nil {
		return err
	}
	useNVD, err := p.confirm("Enrich with NVD (official CVSS/CWE - slower without an NVD key)?", os.Getenv("NVD_API_KEY") != "")
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, "\n4. Report")
	htmlDefault, outputDefault := "report.html", "report.json"
	if inContainer() {
		htmlDefault, outputDefault = "/out/report.html", "/out/report.json"
	}
	html, err := p.ask("HTML report path", htmlDefault, true)
	if err != nil {
		return err
	}
	output, err := p.ask("JSON report path", outputDefault, true)
	if err != nil {
		return err
	}
	rc := runConfig{files: files, output: strings.TrimSpace(output), html: strings.TrimSpace(html), options: pipeline.Options{
		Asset: override, Inventory: inventory, ProviderStatus: "provider_reported",
		Triage: pipeline.TriageOptions{Backend: backend, Jobs: 4},
		Enrich: enrich.Options{UseNVD: useNVD, NVDAPIKey: os.Getenv("NVD_API_KEY"), VendorSources: "auto",
			GitHubToken: githubToken(), UseVulnrichment: true},
	}}
	if evidence != nil {
		cleanup, err := repositoryRun(&rc, evidence)
		if err != nil {
			return err
		}
		defer cleanup()
	}
	for _, w := range rc.warnings {
		fmt.Fprintln(stdout, "warning:", w)
	}
	result, err := execute(ctx, rc, stdout)
	if err != nil {
		return err
	}
	if err := p.offerBrowser(rc.html); err != nil {
		return err
	}
	if !slices.ContainsFunc(result.Actions, func(a pipeline.Action) bool { return a.Kind == "upgrade" && a.TargetVersion != "" }) {
		return nil
	}
	fmt.Fprintln(stdout, "\n5. Local patch - PatchTriage can now prepare one confirmed dependency upgrade in an isolated Git clone.")
	if ok, err := p.confirm("Continue to guided dependency remediation?", false); err != nil || !ok {
		return err
	}
	if err := guidedRemediationWith(p, remediateInputs{report: rc.output, timeout: 600 * time.Second}); err != nil {
		var code exitCode
		if errors.As(err, &code) {
			return err
		}
		return fmt.Errorf("remediation failed: %w", err)
	}
	return nil
}
