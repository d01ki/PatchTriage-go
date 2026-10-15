package remediation

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/d01ki/PatchTriage-go/internal/pipeline"
)

// TestUpdateDependencyManifestsMatchesPython replays
// testdata/remediation_python.json (Python update_dependency_manifests).
func TestUpdateDependencyManifestsMatchesPython(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/remediation_python.json")
	if err != nil {
		t.Fatal(err)
	}
	var data struct {
		Workspaces map[string]map[string]string `json:"workspaces"`
		Cases      map[string]struct {
			Package, Ecosystem, Error string
			Changed                   []string
			Files                     map[string]string
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	for name, c := range data.Cases {
		root := t.TempDir()
		for rel, content := range data.Workspaces[name] {
			path := filepath.Join(root, filepath.FromSlash(rel))
			_ = os.MkdirAll(filepath.Dir(path), 0o755)
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		changed, err := UpdateDependencyManifests(root, pipeline.Action{Kind: "upgrade", Package: c.Package,
			Ecosystem: c.Ecosystem, TargetVersion: "9.9.9"})
		var rels []string
		for _, p := range changed {
			rel, _ := filepath.Rel(root, p)
			rels = append(rels, filepath.ToSlash(rel))
		}
		gotErr := ""
		if err != nil {
			gotErr = err.Error()
		}
		// Python prefixes some errors with the absolute file path.
		errorMatches := gotErr == c.Error
		if i := strings.Index(c.Error, ".json: "); i >= 0 {
			errorMatches = strings.HasSuffix(gotErr, c.Error[i:])
		}
		if !errorMatches || !reflect.DeepEqual(rels, c.Changed) {
			t.Errorf("%s: changed %v err %q; Python changed %v err %q", name, rels, gotErr, c.Changed, c.Error)
		}
		for rel, want := range c.Files {
			got, _ := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
			if string(got) != want {
				t.Errorf("%s/%s:\n got  %q\n want %q", name, rel, got, want)
			}
		}
	}
}

func TestLineEndingsAreKept(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "requirements.txt")
	_ = os.WriteFile(path, []byte("flask\r\nrequests>=2\r\n"), 0o644)
	if _, err := UpdateDependencyManifests(root, pipeline.Action{Kind: "upgrade", Package: "requests", Ecosystem: "pypi",
		TargetVersion: "2.32.4"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != "flask\r\nrequests==2.32.4\r\n" {
		t.Errorf("got %q", got)
	}
}

func TestLockfileCommandsCoverNpmPnpmAndUv(t *testing.T) {
	root := t.TempDir()
	for rel, content := range map[string]string{"npm/package.json": "{}", "npm/package-lock.json": "{}",
		"pnpm/package.json": "{}", "pnpm/pnpm-lock.yaml": "", "python/pyproject.toml": "", "python/uv.lock": ""} {
		path := filepath.Join(root, filepath.FromSlash(rel))
		_ = os.MkdirAll(filepath.Dir(path), 0o755)
		_ = os.WriteFile(path, []byte(content), 0o644)
	}
	npm := LockfileCommands(root, pipeline.Action{}, []string{filepath.Join(root, "npm", "package.json"),
		filepath.Join(root, "pnpm", "package.json")})
	if len(npm) != 2 || npm[0].Command[0] != "npm" || npm[1].Command[0] != "pnpm" {
		t.Errorf("npm commands = %v", npm)
	}
	uv := LockfileCommands(root, pipeline.Action{Package: "requests", TargetVersion: "2.32.4"},
		[]string{filepath.Join(root, "python", "pyproject.toml")})
	if len(uv) != 1 || strings.Join(uv[0].Command, " ") != "uv lock --upgrade-package requests==2.32.4" ||
		uv[0].Dir != filepath.Join(root, "python") {
		t.Errorf("uv commands = %v", uv)
	}
}

func TestParseCheckCommand(t *testing.T) {
	for value, want := range map[string]string{`python -c "print(1)"`: "python|-c|print(1)",
		`npm test -- --grep 'a b'`: "npm|test|--|--grep|a b", `go\ test ./...`: "go test|./..."} {
		got, err := ParseCheckCommand(value)
		if err != nil || strings.Join(got, "|") != want {
			t.Errorf("%q = %q, %v", value, got, err)
		}
	}
	for _, value := range []string{"", "make && make test", `echo "open`} {
		if _, err := ParseCheckCommand(value); err == nil {
			t.Errorf("%q accepted", value)
		}
	}
}

func lodashAction() pipeline.Action {
	return pipeline.Action{ActionID: "upgrade:repo:npm::lodash:4.17.20", Kind: "upgrade", Summary: "Upgrade lodash to 4.17.21",
		Asset: "repo", Package: "lodash", Ecosystem: "npm", InstalledVersion: "4.17.20", TargetVersion: "4.17.21",
		CVEs: []string{"CVE-2021-23337"}}
}

func gitRun(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// repository creates a committed Git working tree with files.
func repository(t *testing.T, files map[string]string) (string, string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	tmp := t.TempDir()
	repo := filepath.Join(tmp, "source")
	_ = os.Mkdir(repo, 0o755)
	gitRun(t, repo, "init", "--quiet")
	gitRun(t, repo, "config", "user.name", "PatchTriage Test")
	gitRun(t, repo, "config", "user.email", "patchtriage@example.invalid")
	gitRun(t, repo, "config", "core.autocrlf", "false")
	for name, content := range files {
		_ = os.WriteFile(filepath.Join(repo, name), []byte(content), 0o644)
	}
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "--quiet", "-m", "fixture")
	return tmp, repo
}

func writeReport(t *testing.T, dir string, actions ...pipeline.Action) string {
	raw, _ := json.Marshal(map[string]any{"actions": actions})
	path := filepath.Join(dir, "report.json")
	_ = os.WriteFile(path, raw, 0o644)
	return path
}

func TestNpmRemediationIsolatedFromSourceAndEmitsPatch(t *testing.T) {
	manifest := "{\n  \"name\": \"fixture\",\n  \"dependencies\": {\n    \"lodash\": \"^4.17.20\"\n  }\n}\n"
	tmp, repo := repository(t, map[string]string{"package.json": manifest})
	report := writeReport(t, tmp, lodashAction())
	result, err := Execute(report, repo, filepath.Join(tmp, "result"), Options{Rescan: false})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "patched_unverified" || result.Branch != "patchtriage/lodash-4.17.21" ||
		strings.Join(result.ChangedFiles, ",") != "package.json" {
		t.Errorf("result = %+v", result)
	}
	if got, _ := os.ReadFile(filepath.Join(repo, "package.json")); string(got) != manifest {
		t.Error("the source checkout was modified")
	}
	patched, _ := os.ReadFile(filepath.Join(result.Workspace, "package.json"))
	patch, _ := os.ReadFile(result.PatchFile)
	if !strings.Contains(string(patched), `"lodash": "4.17.21"`) || !strings.Contains(string(patch), `"lodash": "4.17.21"`) {
		t.Errorf("patched %s / patch %s", patched, patch)
	}
	var artifact map[string]any
	raw, _ := os.ReadFile(filepath.Join(tmp, "result", "remediation.json"))
	if json.Unmarshal(raw, &artifact) != nil || artifact["source_commit"] != gitRun(t, repo, "rev-parse", "HEAD") {
		t.Errorf("artifact = %s", raw)
	}
}

func TestRescanStatusesAndOutputGuard(t *testing.T) {
	tmp, repo := repository(t, map[string]string{"package.json": `{"dependencies":{"lodash":"4.17.20"}}` + "\n"})
	report := writeReport(t, tmp, lodashAction())
	if _, err := Execute(report, repo, filepath.Join(repo, "result"), Options{}); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Errorf("output inside source err = %v", err)
	}
	scanWith := func(body string) runner {
		return func(ctx context.Context, name string, args []string, dir string, env []string) (string, int, error) {
			if name == "fake-osv-scanner" {
				for i, a := range args {
					if a == "--output" {
						_ = os.WriteFile(args[i+1], []byte(body), 0o644)
					}
				}
				return "", 1, nil
			}
			return execRunner(ctx, name, args, dir, env)
		}
	}
	result, err := Execute(report, repo, filepath.Join(tmp, "cleared"), Options{Rescan: true, Scanner: "fake-osv-scanner",
		run: scanWith(`{"results":[]}`)})
	if err != nil || result.Status != "verified" || result.Scan.Status != "cleared" || len(result.Scan.RemainingCVEs) != 0 ||
		result.Commands[len(result.Commands)-1].Kind != "rescan" {
		t.Errorf("cleared = %+v, %v", result, err)
	}
	remaining := `{"results":[{"source":{"path":"package-lock.json"},"packages":[{"package":{"name":"lodash","version":"4.17.21",
		"ecosystem":"npm"},"vulnerabilities":[{"id":"GHSA-35jh-r3h4-6jhm","aliases":["CVE-2021-23337"]}]}]}]}`
	result, err = Execute(report, repo, filepath.Join(tmp, "failed"), Options{Rescan: true, Scanner: "fake-osv-scanner",
		run: scanWith(remaining)})
	if err != nil || result.Status != "verification_failed" || strings.Join(result.Scan.RemainingCVEs, ",") != "CVE-2021-23337" {
		t.Errorf("failed = %+v, %v", result, err)
	}
}

func TestLoadUpgradeActionsFiltersNonPatchActions(t *testing.T) {
	investigate := lodashAction()
	investigate.ActionID, investigate.Kind, investigate.TargetVersion = "investigate:repo:npm::lodash", "investigate", ""
	report := writeReport(t, t.TempDir(), lodashAction(), investigate)
	actions, err := LoadUpgradeActions(report)
	if err != nil || len(actions) != 1 || actions[0].ActionID != lodashAction().ActionID {
		t.Errorf("actions = %+v, %v", actions, err)
	}
}
