// Package remediation creates reviewable dependency patches from
// PatchTriage action reports. It works only on a repository path the
// operator supplies: it clones the committed revision into an isolated
// workspace, updates supported dependency manifests, refreshes supported
// lockfiles with lifecycle scripts disabled, runs explicitly requested
// checks and optionally rescans the workspace with OSV-Scanner.
//
// The source checkout is never modified, and nothing is pushed, merged or
// deployed.
package remediation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/d01ki/PatchTriage-go/internal/ingest"
	"github.com/d01ki/PatchTriage-go/internal/pipeline"
)

// DefaultCommandTimeout bounds every external command.
const DefaultCommandTimeout = 10 * time.Minute

var (
	skipDirectories     = map[string]bool{".git": true, ".hg": true, ".svn": true, ".tox": true, ".venv": true, "node_modules": true, "vendor": true}
	dependencySections  = []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"}
	pyprojectArraySects = map[string]bool{"project": true, "project.optional-dependencies": true, "dependency-groups": true}
	requirementLine     = regexp.MustCompile(`^(?P<indent>\s*)(?P<name>[A-Za-z0-9_.-]+)(?P<extras>\[[^\]]+\])?` +
		`(?P<spec>\s*(?:(?:===|==|~=|!=|<=|>=|<|>)[^;#]*)?)(?P<marker>\s*;[^#]*)?(?P<comment>\s+#.*)?$`)
	// Python matches the closing quote with a backreference; RE2 has none, so
	// each quote style is its own alternative.
	quotedDependency = regexp.MustCompile(`"(?P<dname>[A-Za-z0-9_.-]+)(?P<dextras>\[[^\]]+\])?` +
		`(?P<dspec>(?:(?:===|==|~=|!=|<=|>=|<|>)[^'"]*)?)"|'(?P<sname>[A-Za-z0-9_.-]+)(?P<sextras>\[[^\]]+\])?` +
		`(?P<sspec>(?:(?:===|==|~=|!=|<=|>=|<|>)[^'"]*)?)'`)
	poetryDependency = regexp.MustCompile(`^(?P<indent>\s*)(?P<name>[A-Za-z0-9_.-]+)\s*=\s*(?P<value>.+?)(?P<comment>\s+#.*)?$`)
	poetryVersion    = regexp.MustCompile(`(version\s*=\s*)['"][^'"]*['"]`)
	dependenciesKey  = regexp.MustCompile(`^\s*dependencies\s*=`)
	packageSeparator = regexp.MustCompile(`[-_.]+`)
	unsafeSlug       = regexp.MustCompile(`[^a-z0-9._-]+`)
)

// Error is a patch that could not be prepared safely.
type Error struct{ msg string }

func (e *Error) Error() string { return e.msg }

func fail(format string, args ...any) error { return &Error{fmt.Sprintf(format, args...)} }

// CommandRecord is one executed command.
type CommandRecord struct {
	Command         []string `json:"command"`
	Cwd             string   `json:"cwd"`
	ExitCode        int      `json:"exit_code"`
	DurationSeconds float64  `json:"duration_seconds"`
	Kind            string   `json:"kind"`
}

// ScanRecord is the rescan outcome.
type ScanRecord struct {
	Status        string   `json:"status"`
	Scanner       string   `json:"scanner"`
	Output        string   `json:"output"`
	RemainingCVEs []string `json:"remaining_cves"`
}

// Result is written to remediation.json.
type Result struct {
	Status           string          `json:"status"`
	Action           pipeline.Action `json:"action"`
	SourceRepository string          `json:"source_repository"`
	SourceCommit     string          `json:"source_commit"`
	Branch           string          `json:"branch"`
	Workspace        string          `json:"workspace"`
	ChangedFiles     []string        `json:"changed_files"`
	PatchFile        string          `json:"patch_file"`
	Commands         []CommandRecord `json:"commands"`
	Scan             ScanRecord      `json:"scan"`
	Warnings         []string        `json:"warnings"`
}

func normalizedPackage(name string) string {
	return strings.ToLower(packageSeparator.ReplaceAllString(name, "-"))
}

// iterFiles lists files named one of names (or starting with a prefix),
// case-insensitively, skipping vendored and VCS directories.
func iterFiles(root string, names []string, prefixes ...string) []string {
	var out []string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if path != root && skipDirectories[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		lower := strings.ToLower(d.Name())
		for _, n := range names {
			if lower == strings.ToLower(n) {
				out = append(out, path)
				return nil
			}
		}
		for _, p := range prefixes {
			if strings.HasPrefix(lower, strings.ToLower(p)) {
				out = append(out, path)
				return nil
			}
		}
		return nil
	})
	return out
}

// textFile is a manifest read as text with its line-ending style, so an
// edit changes only the edited lines.
type textFile struct {
	text string
	crlf bool
}

func readText(path string) (textFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return textFile{}, err
	}
	text := string(raw)
	crlf := strings.Contains(text, "\r\n")
	return textFile{strings.ReplaceAll(text, "\r\n", "\n"), crlf}, nil
}

func writeText(path string, f textFile, text string) error {
	if f.crlf {
		text = strings.ReplaceAll(text, "\n", "\r\n")
	}
	return os.WriteFile(path, []byte(text), 0o644)
}

func updatePackageJSON(path, pkg, target string) (bool, error) {
	f, err := readText(path)
	if err != nil {
		return false, fail("could not read %s: %s", path, err)
	}
	doc, err := decodeOrdered([]byte(f.text))
	if err != nil {
		return false, fail("could not read %s: %s", path, err)
	}
	changed := false
	if doc.kind == '{' {
		for _, section := range dependencySections {
			deps := doc.get(section)
			if deps == nil || deps.kind != '{' {
				continue
			}
			for i, name := range deps.keys {
				if normalizedPackage(name) != normalizedPackage(pkg) {
					continue
				}
				value := deps.values[i]
				if value.kind != '"' {
					return false, fail("%s: dependency %s is not a string", path, name)
				}
				for _, prefix := range []string{"file:", "git+", "http:", "https:", "workspace:"} {
					if strings.HasPrefix(value.text, prefix) {
						return false, fail("%s: dependency %s uses a non-registry source", path, name)
					}
				}
				if value.text != target {
					deps.values[i] = &node{kind: '"', text: target}
					changed = true
				}
			}
		}
	}
	if !changed {
		return false, nil
	}
	indent := 2
	if strings.Contains(f.text, "\n    \"") {
		indent = 4
	}
	var b strings.Builder
	doc.write(&b, indent, 0)
	if strings.HasSuffix(f.text, "\n") {
		b.WriteString("\n")
	}
	return true, writeText(path, f, b.String())
}

// splitLines is Python's str.splitlines(keepends=True) for "\n" text.
func splitLines(text string) []string {
	var out []string
	for text != "" {
		i := strings.IndexByte(text, '\n')
		if i < 0 {
			return append(out, text)
		}
		out, text = append(out, text[:i+1]), text[i+1:]
	}
	return out
}

func group(re *regexp.Regexp, m []string, name string) string { return m[re.SubexpIndex(name)] }

func updateRequirements(path, pkg, target string) (bool, error) {
	f, err := readText(path)
	if err != nil {
		return false, fail("could not read %s: %s", path, err)
	}
	var out strings.Builder
	changed := false
	for _, line := range splitLines(f.text) {
		content, newline := strings.CutSuffix(line, "\n")
		m := requirementLine.FindStringSubmatch(content)
		if m == nil || normalizedPackage(group(requirementLine, m, "name")) != normalizedPackage(pkg) {
			out.WriteString(line)
			continue
		}
		replacement := group(requirementLine, m, "indent") + group(requirementLine, m, "name") +
			group(requirementLine, m, "extras") + "==" + target + group(requirementLine, m, "marker") +
			group(requirementLine, m, "comment")
		if newline {
			replacement += "\n"
		}
		out.WriteString(replacement)
		changed = changed || replacement != line
	}
	if !changed || out.String() == f.text {
		return false, nil
	}
	return true, writeText(path, f, out.String())
}

func replaceQuotedDependency(line, pkg, target string) (string, bool) {
	changed := false
	out := quotedDependency.ReplaceAllStringFunc(line, func(match string) string {
		m := quotedDependency.FindStringSubmatch(match)
		quote, name, extras := `"`, group(quotedDependency, m, "dname"), group(quotedDependency, m, "dextras")
		if name == "" {
			quote, name, extras = "'", group(quotedDependency, m, "sname"), group(quotedDependency, m, "sextras")
		}
		if normalizedPackage(name) != normalizedPackage(pkg) {
			return match
		}
		changed = true
		return quote + name + extras + "==" + target + quote
	})
	return out, changed
}

func replacePoetryDependency(line, pkg, target string) (string, bool, error) {
	m := poetryDependency.FindStringSubmatch(strings.TrimRight(line, "\n"))
	if m == nil || normalizedPackage(group(poetryDependency, m, "name")) != normalizedPackage(pkg) {
		return line, false, nil
	}
	value := strings.TrimSpace(group(poetryDependency, m, "value"))
	switch {
	case strings.HasPrefix(value, "{"):
		loc := poetryVersion.FindStringSubmatchIndex(value)
		if loc == nil {
			return "", false, fail("Poetry inline dependency has no editable version field")
		}
		value = value[:loc[0]] + value[loc[2]:loc[3]] + `"` + target + `"` + value[loc[1]:]
	case strings.HasPrefix(value, "'") || strings.HasPrefix(value, `"`):
		value = value[:1] + target + value[:1]
	default:
		return "", false, fail("Poetry dependency uses an unsupported non-string constraint")
	}
	out := group(poetryDependency, m, "indent") + group(poetryDependency, m, "name") + " = " + value +
		group(poetryDependency, m, "comment")
	if strings.HasSuffix(line, "\n") {
		out += "\n"
	}
	return out, true, nil
}

func updatePyproject(path, pkg, target string) (bool, error) {
	f, err := readText(path)
	if err != nil {
		return false, fail("could not read %s: %s", path, err)
	}
	section := ""
	var out strings.Builder
	changed, inProjectDependencies := false, false
	for _, line := range splitLines(f.text) {
		stripped := strings.TrimSpace(line)
		if strings.HasPrefix(stripped, "[") && strings.HasSuffix(stripped, "]") {
			section = strings.ToLower(strings.TrimSpace(strings.Trim(stripped, "[]")))
			inProjectDependencies = false
			out.WriteString(line)
			continue
		}
		processArray := false
		switch {
		case section == "project":
			if !inProjectDependencies && dependenciesKey.MatchString(line) {
				inProjectDependencies = true
			}
			processArray = inProjectDependencies
		case pyprojectArraySects[section] || strings.HasPrefix(section, "project.optional-dependencies") ||
			strings.HasPrefix(section, "dependency-groups"):
			processArray = true
		}
		lineChanged := false
		switch {
		case processArray:
			line, lineChanged = replaceQuotedDependency(line, pkg, target)
			if section == "project" && strings.Contains(line, "]") {
				inProjectDependencies = false
			}
		case section == "tool.poetry.dependencies" ||
			strings.HasPrefix(section, "tool.poetry.group.") && strings.HasSuffix(section, ".dependencies"):
			if line, lineChanged, err = replacePoetryDependency(line, pkg, target); err != nil {
				return false, err
			}
		}
		changed = changed || lineChanged
		out.WriteString(line)
	}
	if !changed || out.String() == f.text {
		return false, nil
	}
	return true, writeText(path, f, out.String())
}

// UpdateDependencyManifests updates supported direct dependency
// declarations for one upgrade action and returns the changed files.
func UpdateDependencyManifests(workspace string, a pipeline.Action) ([]string, error) {
	if a.Kind != "upgrade" || a.TargetVersion == "" {
		return nil, fail("the selected action has no confirmed upgrade")
	}
	type editor struct {
		names    []string
		prefixes []string
		update   func(path, pkg, target string) (bool, error)
	}
	var editors []editor
	switch strings.ToLower(a.Ecosystem) {
	case "npm", "node", "javascript":
		editors = []editor{{[]string{"package.json"}, nil, updatePackageJSON}}
	case "pypi", "python", "pip":
		editors = []editor{{[]string{"pyproject.toml"}, nil, updatePyproject},
			{[]string{"requirements.txt"}, []string{"requirements-", "requirements."}, updateRequirements}}
	default:
		raw, _ := json.Marshal(a.Ecosystem)
		return nil, fail("automatic remediation is not supported for ecosystem '%s'", strings.Trim(string(raw), `"`))
	}
	seen := map[string]bool{}
	var changed []string
	for _, e := range editors {
		for _, path := range iterFiles(workspace, e.names, e.prefixes...) {
			ok, err := e.update(path, a.Package, a.TargetVersion)
			if err != nil {
				return nil, err
			}
			if ok && !seen[path] {
				seen[path] = true
				changed = append(changed, path)
			}
		}
	}
	if len(changed) == 0 {
		return nil, fail("no supported direct declaration of '%s' was found", a.Package)
	}
	sort.Strings(changed)
	return changed, nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// nearestLockRoot finds the closest directory (up to workspace) holding
// one of lockNames.
func nearestLockRoot(path, workspace string, lockNames ...string) (string, string, bool) {
	dir := filepath.Dir(path)
	for {
		for _, name := range lockNames {
			if exists(filepath.Join(dir, name)) {
				return dir, name, true
			}
		}
		parent := filepath.Dir(dir)
		if filepath.Clean(dir) == filepath.Clean(workspace) || parent == dir {
			return "", "", false
		}
		dir = parent
	}
}

// LockCommand is one lockfile refresh command and its directory.
type LockCommand struct {
	Command []string
	Dir     string
}

// LockfileCommands returns deterministic lockfile refresh commands for the
// changed manifests (one per directory and tool).
func LockfileCommands(workspace string, a pipeline.Action, changed []string) []LockCommand {
	var out []LockCommand
	index := map[string]int{}
	for _, path := range changed {
		var command []string
		var root string
		switch filepath.Base(path) {
		case "package.json":
			dir, name, ok := nearestLockRoot(path, workspace, "pnpm-lock.yaml", "package-lock.json")
			if !ok {
				continue
			}
			root, command = dir, []string{"npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"}
			if name == "pnpm-lock.yaml" {
				command = []string{"pnpm", "install", "--lockfile-only", "--ignore-scripts"}
			}
		case "pyproject.toml":
			dir, _, ok := nearestLockRoot(path, workspace, "uv.lock")
			if !ok {
				continue
			}
			root, command = dir, []string{"uv", "lock", "--upgrade-package", a.Package + "==" + a.TargetVersion}
		default:
			continue
		}
		key := root + "\x00" + command[0]
		if i, ok := index[key]; ok {
			out[i] = LockCommand{command, root}
			continue
		}
		index[key] = len(out)
		out = append(out, LockCommand{command, root})
	}
	return out
}

// ParseCheckCommand tokenizes a portable argument string (POSIX shlex
// rules); shell operators are rejected because no shell runs it.
func ParseCheckCommand(value string) ([]string, error) {
	command, err := shlexSplit(value)
	if err != nil {
		return nil, err
	}
	if len(command) == 0 {
		return nil, fail("check command cannot be empty")
	}
	for _, token := range command {
		switch token {
		case "&&", "||", ";", "|", ">", ">>", "<":
			return nil, fail("check commands do not accept shell operators; repeat --check for multiple commands")
		}
	}
	return command, nil
}

// shlexSplit is Python's shlex.split(value, posix=True).
func shlexSplit(s string) ([]string, error) {
	var out []string
	var token strings.Builder
	inToken := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			if inToken {
				out, inToken = append(out, token.String()), false
				token.Reset()
			}
		case c == '\\':
			inToken = true
			if i+1 < len(s) {
				i++
				token.WriteByte(s[i])
			}
		case c == '\'':
			inToken = true
			end := strings.IndexByte(s[i+1:], '\'')
			if end < 0 {
				return nil, errors.New("No closing quotation")
			}
			token.WriteString(s[i+1 : i+1+end])
			i += end + 1
		case c == '"':
			inToken = true
			i++
			for ; ; i++ {
				if i >= len(s) {
					return nil, errors.New("No closing quotation")
				}
				if s[i] == '"' {
					break
				}
				if s[i] == '\\' && i+1 < len(s) && strings.IndexByte("\\\"$`\n", s[i+1]) >= 0 {
					i++
				}
				token.WriteByte(s[i])
			}
		default:
			inToken = true
			token.WriteByte(c)
		}
	}
	if inToken {
		out = append(out, token.String())
	}
	return out, nil
}

// runner executes a command; tests replace it.
type runner func(ctx context.Context, name string, args []string, dir string, env []string) (stdout string, exitCode int, err error)

func execRunner(ctx context.Context, name string, args []string, dir string, env []string) (string, int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir, cmd.Env = dir, env
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	err := cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return stdout.String(), exitErr.ExitCode(), nil
	}
	return stdout.String(), 0, err
}

func round3(seconds float64) float64 { return math.Round(seconds*1000) / 1000 }

// Options control one remediation run.
type Options struct {
	ActionID         string
	Checks           []string
	RefreshLockfiles bool
	Rescan           bool
	Scanner          string
	Timeout          time.Duration
	run              runner
}

type executor struct {
	o   Options
	env []string
}

func (e executor) command(name string, args []string, dir, kind string) (CommandRecord, error) {
	executable, err := exec.LookPath(name)
	if err != nil {
		return CommandRecord{}, fail("required executable '%s' was not found", name)
	}
	ctx, cancel := context.WithTimeout(context.Background(), e.o.Timeout)
	defer cancel()
	started := time.Now()
	_, code, err := e.o.run(ctx, executable, args, dir, e.env)
	if ctx.Err() != nil {
		return CommandRecord{}, fail("%s command timed out after %d seconds", kind, int(e.o.Timeout.Seconds()))
	}
	if err != nil {
		return CommandRecord{}, err
	}
	record := CommandRecord{Command: append([]string{name}, args...), Cwd: dir, ExitCode: code,
		DurationSeconds: round3(time.Since(started).Seconds()), Kind: kind}
	if code != 0 {
		return CommandRecord{}, fail("%s command failed with exit code %d: %s", kind, code, name)
	}
	return record, nil
}

func (e executor) git(git, dir string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultCommandTimeout)
	defer cancel()
	out, code, err := e.o.run(ctx, git, args, dir, nil)
	if err != nil {
		return "", err
	}
	if code != 0 {
		return "", fail("git command failed with exit code %d", code)
	}
	return out, nil
}

func safeSlug(value string) string {
	slug := strings.Trim(unsafeSlug.ReplaceAllString(strings.ToLower(value), "-"), "-._")
	if slug == "" {
		slug = "dependency"
	}
	return string([]rune(slug)[:min(48, utf8.RuneCountInString(slug))])
}

// LoadUpgradeActions loads the ordered, confirmed dependency upgrades of a
// JSON report.
func LoadUpgradeActions(reportPath string) ([]pipeline.Action, error) {
	raw, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, fail("could not read report: %s", err)
	}
	var report map[string]json.RawMessage
	if !json.Valid(raw) {
		return nil, fail("could not read report: invalid JSON")
	}
	if json.Unmarshal(raw, &report) != nil {
		return nil, fail("report must contain a JSON object")
	}
	var entries []json.RawMessage
	if len(report["actions"]) > 0 && json.Unmarshal(report["actions"], &entries) != nil {
		return nil, fail("report contains an invalid remediation action")
	}
	var actions []pipeline.Action
	for _, entry := range entries {
		a, err := decodeAction(entry)
		if err != nil {
			return nil, err
		}
		actions = append(actions, a)
	}
	var out []pipeline.Action
	for _, a := range actions {
		if a.Kind == "upgrade" && a.TargetVersion != "" {
			out = append(out, a)
		}
	}
	return out, nil
}

// decodeAction validates one report action like the Python model: required
// identity fields, and the model defaults for everything omitted.
func decodeAction(raw json.RawMessage) (pipeline.Action, error) {
	invalid := fail("report contains an invalid remediation action")
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return pipeline.Action{}, invalid
	}
	for _, key := range []string{"action_id", "kind", "summary", "asset", "package"} {
		if _, ok := fields[key]; !ok {
			return pipeline.Action{}, invalid
		}
	}
	a := pipeline.Action{TopPriority: "P4", DeadlineDays: 90}
	if json.Unmarshal(raw, &a) != nil {
		return pipeline.Action{}, invalid
	}
	for _, list := range []*[]string{&a.TargetVersionCandidates, &a.FindingKeys, &a.CVEs, &a.Rationales, &a.Obligations} {
		if *list == nil {
			*list = []string{}
		}
	}
	return a, nil
}

func selectAction(actions []pipeline.Action, id string) (pipeline.Action, error) {
	if id != "" {
		for _, a := range actions {
			if a.ActionID == id {
				return a, nil
			}
		}
		return pipeline.Action{}, fail("no upgrade action matches '%s'", id)
	}
	if len(actions) == 0 {
		return pipeline.Action{}, fail("the report contains no confirmed upgrade action")
	}
	return actions[0], nil
}

func scanRemainingCVEs(scanPath string, expected []string) ([]string, error) {
	result, err := ingest.LoadFile(context.Background(), scanPath, "osv", nil, nil)
	if err != nil {
		return nil, fail("OSV-Scanner output could not be parsed")
	}
	observed := map[string]bool{}
	for _, f := range result.Findings {
		for _, id := range append([]string{f.VulnID}, f.Aliases...) {
			observed[strings.ToUpper(id)] = true
		}
	}
	remaining := []string{}
	seen := map[string]bool{}
	for _, cve := range expected {
		if id := strings.ToUpper(cve); observed[id] && !seen[id] {
			seen[id] = true
			remaining = append(remaining, id)
		}
	}
	sort.Strings(remaining)
	return remaining, nil
}

func within(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// Execute prepares one dependency patch in an isolated, PR-ready clone and
// writes remediation.patch and remediation.json into outputDir.
func Execute(reportPath, repository, outputDir string, o Options) (*Result, error) {
	if o.Timeout == 0 {
		o.Timeout = DefaultCommandTimeout
	}
	if o.run == nil {
		o.run = execRunner
	}
	repository, _ = filepath.Abs(repository)
	outputDir, _ = filepath.Abs(outputDir)
	if info, err := os.Stat(repository); err != nil || !info.IsDir() || !exists(filepath.Join(repository, ".git")) {
		return nil, fail("repository must be a local Git working tree")
	}
	if within(outputDir, repository) {
		return nil, fail("output directory must be outside the source repository")
	}
	if info, err := os.Stat(outputDir); err == nil {
		if !info.IsDir() {
			return nil, fail("output directory path is not a directory")
		}
		if entries, _ := os.ReadDir(outputDir); len(entries) > 0 {
			return nil, fail("output directory must be empty or absent")
		}
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return nil, err
	}
	actions, err := LoadUpgradeActions(reportPath)
	if err != nil {
		return nil, err
	}
	action, err := selectAction(actions, o.ActionID)
	if err != nil {
		return nil, err
	}
	git, err := exec.LookPath("git")
	if err != nil {
		return nil, fail("git is required for remediation")
	}
	e := executor{o: o}
	warnings := []string{}
	status, err := e.git(git, repository, "-c", "safe.directory="+repository, "status", "--porcelain")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(status) != "" {
		warnings = append(warnings, "source working-tree changes were not included; remediation uses the committed HEAD")
	}
	workspace := filepath.Join(outputDir, "workspace")
	if _, err := e.git(git, "", "-c", "safe.directory="+repository, "clone", "--quiet", "--local", "--no-hardlinks",
		repository, workspace); err != nil {
		return nil, err
	}
	commit, err := e.git(git, workspace, "rev-parse", "HEAD")
	if err != nil {
		return nil, err
	}
	branch := "patchtriage/" + safeSlug(action.Package) + "-" + safeSlug(action.TargetVersion)
	if _, err := e.git(git, workspace, "switch", "-c", branch); err != nil {
		return nil, err
	}
	manifests, err := UpdateDependencyManifests(workspace, action)
	if err != nil {
		return nil, err
	}
	e.env = append(os.Environ(), "CI=true", "NPM_CONFIG_AUDIT=false", "NPM_CONFIG_FUND=false",
		"NPM_CONFIG_IGNORE_SCRIPTS=true", "npm_config_ignore_scripts=true")
	records := []CommandRecord{}
	locks := LockfileCommands(workspace, action, manifests)
	for _, manifest := range manifests {
		var unsupported []string
		switch filepath.Base(manifest) {
		case "package.json":
			unsupported = []string{"yarn.lock"}
		case "pyproject.toml":
			unsupported = []string{"poetry.lock", "Pipfile.lock"}
		}
		if _, name, ok := nearestLockRoot(manifest, workspace, unsupported...); ok {
			warnings = append(warnings, name+" is present but its automatic refresh is not supported")
		}
	}
	if o.RefreshLockfiles {
		for _, lock := range locks {
			record, err := e.command(lock.Command[0], lock.Command[1:], lock.Dir, "lockfile")
			if err != nil {
				return nil, err
			}
			records = append(records, record)
		}
	} else if len(locks) > 0 {
		warnings = append(warnings, "lockfile refresh was explicitly skipped")
	}
	for _, value := range o.Checks {
		command, err := ParseCheckCommand(value)
		if err != nil {
			return nil, err
		}
		record, err := e.command(command[0], command[1:], workspace, "check")
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}

	scan := ScanRecord{Status: "skipped", RemainingCVEs: []string{}}
	if o.Rescan {
		scanner := o.Scanner
		if scanner == "" {
			scanner, _ = exec.LookPath("osv-scanner")
		}
		if scanner == "" {
			warnings = append(warnings, "OSV-Scanner was not found; rescan skipped")
		} else {
			scanPath := filepath.Join(outputDir, "osv-remediation.json")
			config := filepath.Join(outputDir, "trusted-osv-scanner.toml")
			if err := os.WriteFile(config, nil, 0o644); err != nil {
				return nil, err
			}
			args := []string{"--config", config, "scan", "source", "--format", "json", "--output", scanPath,
				"--no-resolve", "--all-packages", workspace}
			ctx, cancel := context.WithTimeout(context.Background(), o.Timeout)
			started := time.Now()
			_, code, err := o.run(ctx, scanner, args, workspace, e.env)
			cancel()
			if err != nil {
				return nil, err
			}
			records = append(records, CommandRecord{Command: append([]string{"osv-scanner"}, args...), Cwd: workspace,
				ExitCode: code, DurationSeconds: round3(time.Since(started).Seconds()), Kind: "rescan"})
			if code != 0 && code != 1 {
				return nil, fail("OSV-Scanner remediation scan failed with exit code %d", code)
			}
			if !exists(scanPath) {
				return nil, fail("OSV-Scanner did not produce remediation output")
			}
			remaining, err := scanRemainingCVEs(scanPath, action.CVEs)
			if err != nil {
				return nil, err
			}
			scan = ScanRecord{Status: "cleared", Scanner: "osv-scanner", Output: scanPath, RemainingCVEs: remaining}
			if len(remaining) > 0 {
				scan.Status = "failed"
			}
		}
	}

	diff, err := e.git(git, workspace, "diff", "--binary", "--no-ext-diff")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(diff) == "" {
		return nil, fail("remediation produced no repository diff")
	}
	patchFile := filepath.Join(outputDir, "remediation.patch")
	if err := os.WriteFile(patchFile, []byte(diff), 0o644); err != nil {
		return nil, err
	}
	statusOutput, err := e.git(git, workspace, "status", "--porcelain")
	if err != nil {
		return nil, err
	}
	files := map[string]bool{}
	for _, line := range strings.Split(statusOutput, "\n") {
		if len(line) > 3 {
			files[strings.TrimSpace(line[3:])] = true
		}
	}
	changed := make([]string, 0, len(files))
	for f := range files {
		changed = append(changed, f)
	}
	sort.Strings(changed)
	checksRequested := false
	for _, r := range records {
		checksRequested = checksRequested || r.Kind == "check"
	}
	result := &Result{Action: action, SourceRepository: repository, SourceCommit: strings.TrimSpace(commit), Branch: branch,
		Workspace: workspace, ChangedFiles: changed, PatchFile: patchFile, Commands: records, Scan: scan, Warnings: warnings}
	switch {
	case scan.Status == "failed":
		result.Status = "verification_failed"
	case scan.Status == "cleared" || checksRequested:
		result.Status = "verified"
	default:
		result.Status = "patched_unverified"
	}
	raw, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, err
	}
	return result, os.WriteFile(filepath.Join(outputDir, "remediation.json"), raw, 0o644)
}

// ------------------------------------------------------------ ordered JSON

// node is a decoded JSON value that keeps object member order, so a
// rewritten package.json reads like Python's json.dumps of the loaded dict.
type node struct {
	kind   byte // '{' object, '[' array, '"' string, '0' number, 'l' literal
	text   string
	keys   []string
	values []*node
}

func (n *node) get(key string) *node {
	for i, k := range n.keys {
		if k == key {
			return n.values[i]
		}
	}
	return nil
}

func decodeOrdered(raw []byte) (*node, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	n, err := decodeNode(d)
	if err != nil {
		return nil, err
	}
	if d.More() {
		return nil, errors.New("extra data after the JSON document")
	}
	return n, nil
}

func decodeNode(d *json.Decoder) (*node, error) {
	tok, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		n := &node{kind: byte(t)}
		for d.More() {
			if t == '{' {
				keyTok, err := d.Token()
				if err != nil {
					return nil, err
				}
				key := keyTok.(string)
				value, err := decodeNode(d)
				if err != nil {
					return nil, err
				}
				if existing := n.get(key); existing != nil {
					*existing = *value // a repeated key keeps its first position, last value
					continue
				}
				n.keys, n.values = append(n.keys, key), append(n.values, value)
			} else {
				value, err := decodeNode(d)
				if err != nil {
					return nil, err
				}
				n.values = append(n.values, value)
			}
		}
		if _, err := d.Token(); err != nil {
			return nil, err
		}
		return n, nil
	case string:
		return &node{kind: '"', text: t}, nil
	case json.Number:
		return &node{kind: '0', text: pyNumber(string(t))}, nil
	case bool:
		return &node{kind: 'l', text: fmt.Sprint(t)}, nil
	}
	return &node{kind: 'l', text: "null"}, nil
}

// pyNumber renders a JSON number as Python's json.dumps(json.loads(x)).
func pyNumber(literal string) string {
	if !strings.ContainsAny(literal, ".eE") {
		return literal
	}
	var f float64
	if _, err := fmt.Sscan(literal, &f); err != nil {
		return literal
	}
	exp := 0
	if f != 0 {
		exp = int(math.Floor(math.Log10(math.Abs(f))))
	}
	if exp < -4 || exp >= 16 {
		return strconv.FormatFloat(f, 'e', -1, 64)
	}
	s := strconv.FormatFloat(f, 'f', -1, 64)
	if !strings.Contains(s, ".") {
		s += ".0"
	}
	return s
}

// pyString is json.dumps(s, ensure_ascii=False).
func pyString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

func (n *node) write(b *strings.Builder, indent, level int) {
	pad := func(l int) string { return "\n" + strings.Repeat(" ", indent*l) }
	switch n.kind {
	case '{', '[':
		closing := byte('}')
		if n.kind == '[' {
			closing = ']'
		}
		b.WriteByte(n.kind)
		if len(n.values) == 0 {
			b.WriteByte(closing)
			return
		}
		for i, v := range n.values {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(pad(level + 1))
			if n.kind == '{' {
				b.WriteString(pyString(n.keys[i]) + ": ")
			}
			v.write(b, indent, level+1)
		}
		b.WriteString(pad(level))
		b.WriteByte(closing)
	case '"':
		b.WriteString(pyString(n.text))
	default:
		b.WriteString(n.text)
	}
}
