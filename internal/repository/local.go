package repository

// Opt-in local scanner for public HTTPS Git repositories, unavailable in
// public mode. It clones into a disposable directory and asks osv-scanner to
// inspect lockfiles without installing dependencies or executing repository
// code. Provider-backed imports remain preferable because they avoid exposing
// the process to arbitrary Git servers.

import (
	"context"
	"encoding/json"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	defaultCloneTimeout    = 120 * time.Second
	defaultScanTimeout     = 180 * time.Second
	defaultRepositoryBytes = 512 * 1024 * 1024
	defaultRepositoryFiles = 100_000
	defaultOutputBytes     = 16 * 1024 * 1024
	toolLogBytes           = 1024 * 1024
	processPoll            = 100 * time.Millisecond
	maxDetectedManifests   = 500
)

var lockfileNames = map[string]bool{
	"cargo.lock": true, "composer.lock": true, "deps.edn": true, "gemfile.lock": true, "go.mod": true,
	"gradle.lockfile": true, "mix.lock": true, "package-lock.json": true, "packages.lock.json": true,
	"packages.resolved": true, "pipfile.lock": true, "pnpm-lock.yaml": true, "poetry.lock": true,
	"pubspec.lock": true, "renv.lock": true, "yarn.lock": true,
}

// LocalScanner clones and statically scans an allowed public repository.
// Zero fields use PATH lookups and Python's limits.
type LocalScanner struct {
	Git, Scanner              string
	CloneTimeout, ScanTimeout time.Duration
	MaxBytes, MaxOutputBytes  int64
	MaxFiles                  int
	Resolve                   func(ctx context.Context, host string) ([]string, error)
}

// nonGlobal lists the ranges Python's ipaddress does not call global.
var nonGlobal = func() []netip.Prefix {
	var out []netip.Prefix
	for _, p := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "240.0.0.0/4", "255.255.255.255/32", "::/128", "::1/128", "::ffff:0:0/96", "64:ff9b:1::/48",
		"100::/64", "2001::/23", "2001:db8::/32", "2002::/16", "fc00::/7", "fe80::/10"} {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}()

func isGlobal(addr netip.Addr) bool {
	for _, p := range nonGlobal {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

// publicAddresses resolves host once and rejects every non-global answer.
// This is defense in depth, not a replacement for an egress firewall, which
// is why the adapter is disabled in public mode.
func (s LocalScanner) publicAddresses(ctx context.Context, host string) ([]string, error) {
	resolve := s.Resolve
	if resolve == nil {
		resolve = net.DefaultResolver.LookupHost
	}
	answers, err := resolve(ctx, host)
	if err != nil {
		return nil, fetchError("repository host could not be resolved: %s", host)
	}
	seen := map[string]bool{}
	var addresses []string
	for _, a := range answers {
		a, _, _ = strings.Cut(a, "%")
		if !seen[a] {
			seen[a] = true
			addresses = append(addresses, a)
		}
	}
	sort.Strings(addresses)
	if len(addresses) == 0 {
		return nil, fetchError("repository host resolved to no addresses")
	}
	for _, value := range addresses {
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return nil, fetchError("repository host returned an invalid address")
		}
		if !isGlobal(addr.Unmap()) {
			return nil, fetchError("repository host resolves to a private, local, reserved, or otherwise non-public "+
				"address (%s)", value)
		}
	}
	return addresses, nil
}

func toolEnvironment(home string) []string {
	keep := map[string]bool{"PATH": true, "PATHEXT": true, "SYSTEMROOT": true, "WINDIR": true, "COMSPEC": true,
		"TEMP": true, "TMP": true, "LANG": true, "LC_ALL": true}
	var env []string
	for _, kv := range os.Environ() {
		if key, _, _ := strings.Cut(kv, "="); keep[strings.ToUpper(key)] {
			env = append(env, kv)
		}
	}
	return append(env, "GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_NOSYSTEM=1", "GIT_LFS_SKIP_SMUDGE=1",
		"HOME="+home, "USERPROFILE="+home)
}

// enforcePathLimits bounds a growing file or tree while a tool runs.
func enforcePathLimits(path string, maxBytes int64, maxFiles int, label string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return nil
	}
	var total int64
	count := 0
	check := func(size int64) error {
		count++
		if maxFiles > 0 && count > maxFiles {
			return tooLarge("%s contains more than %d files", label, maxFiles)
		}
		total += size
		if maxBytes > 0 && total > maxBytes {
			return tooLarge("%s exceeds the %d-byte limit", label, maxBytes)
		}
		return nil
	}
	if !info.IsDir() {
		return check(info.Size())
	}
	return filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		return check(fi.Size())
	})
}

type completed struct {
	code           int
	stdout, stderr string
}

// timeoutError marks a tool that ran past its deadline.
type timeoutError struct{}

func (timeoutError) Error() string { return "timeout" }

// runMonitored runs a tool while bounding its filesystem growth and logs,
// stopping the whole process tree on any violation.
func runMonitored(command []string, env []string, timeout time.Duration, monitor string, maxBytes int64,
	maxFiles int, label string) (completed, error) {
	stdout, err := os.CreateTemp("", "patchtriage-tool-*")
	if err != nil {
		return completed{}, err
	}
	defer os.Remove(stdout.Name())
	defer stdout.Close()
	stderr, err := os.CreateTemp("", "patchtriage-tool-*")
	if err != nil {
		return completed{}, err
	}
	defer os.Remove(stderr.Name())
	defer stderr.Close()

	cmd := exec.Command(command[0], command[1:]...)
	cmd.Env, cmd.Stdout, cmd.Stderr = env, stdout, stderr
	newProcessGroup(cmd)
	if err := cmd.Start(); err != nil {
		return completed{}, fetchError("%s could not start: %s", label, err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	deadline := time.Now().Add(timeout)
	check := func() error {
		if err := enforcePathLimits(monitor, maxBytes, maxFiles, label); err != nil {
			return err
		}
		for _, f := range []*os.File{stdout, stderr} {
			if info, err := f.Stat(); err == nil && info.Size() > toolLogBytes {
				return fetchError("%s produced excessive diagnostic output", label)
			}
		}
		return nil
	}
	ticker := time.NewTicker(processPoll)
	defer ticker.Stop()
	for {
		if err := check(); err != nil {
			stopTree(cmd, done)
			return completed{}, err
		}
		select {
		case <-done:
			// Close the race between the last check and the process exit.
			if err := check(); err != nil {
				return completed{}, err
			}
			out, _ := os.ReadFile(stdout.Name())
			errText, _ := os.ReadFile(stderr.Name())
			return completed{cmd.ProcessState.ExitCode(), strings.ToValidUTF8(string(out), "�"),
				strings.ToValidUTF8(string(errText), "�")}, nil
		case <-ticker.C:
			if time.Now().After(deadline) {
				stopTree(cmd, done)
				return completed{}, timeoutError{}
			}
		}
	}
}

func lastChars(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	return string(r[max(0, len(r)-n):])
}

func toolFailure(prefix string, c completed) error {
	detail := c.stderr
	if strings.TrimSpace(detail) == "" {
		detail = c.stdout
	}
	if detail = lastChars(detail, 600); detail != "" {
		return fetchError("%s: %s", prefix, detail)
	}
	return fetchError("%s", prefix)
}

func repositoryInventory(root string, maxBytes int64, maxFiles int) (int, int64, []string, error) {
	count, total := 0, int64(0)
	manifests := []string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		count++
		if count > maxFiles {
			return tooLarge("repository contains more than %d files", maxFiles)
		}
		if info, err := d.Info(); err == nil {
			total += info.Size()
		}
		if total > maxBytes {
			return tooLarge("repository checkout exceeds the %d-byte limit", maxBytes)
		}
		lower := strings.ToLower(d.Name())
		if lockfileNames[lower] || strings.HasSuffix(lower, ".csproj") || strings.HasSuffix(lower, ".fsproj") ||
			strings.HasSuffix(lower, ".gemspec") || strings.HasSuffix(lower, ".gradle") {
			rel, _ := filepath.Rel(root, path)
			manifests = append(manifests, filepath.ToSlash(rel))
		}
		return nil
	})
	return count, total, manifests[:min(len(manifests), maxDetectedManifests)], err
}

// Scan clones and statically scans an explicitly allowed public repository.
func (s LocalScanner) Scan(ctx context.Context, ref Reference) (Evidence, error) {
	if _, err := s.publicAddresses(ctx, ref.Host); err != nil {
		return Evidence{}, err
	}
	git, scanner := s.Git, s.Scanner
	if git == "" {
		git, _ = exec.LookPath("git")
	}
	if scanner == "" {
		scanner, _ = exec.LookPath("osv-scanner")
	}
	if git == "" || scanner == "" {
		return Evidence{}, fetchError("generic repository scanning requires git and osv-scanner; use the Docker GUI " +
			"or install both tools locally")
	}
	cloneTimeout, scanTimeout := orDuration(s.CloneTimeout, defaultCloneTimeout), orDuration(s.ScanTimeout, defaultScanTimeout)
	maxBytes, maxOutput := orInt64(s.MaxBytes, defaultRepositoryBytes), orInt64(s.MaxOutputBytes, defaultOutputBytes)
	maxFiles := s.MaxFiles
	if maxFiles == 0 {
		maxFiles = defaultRepositoryFiles
	}

	tmp, err := os.MkdirTemp("", "patchtriage-repository-")
	if err != nil {
		return Evidence{}, err
	}
	defer os.RemoveAll(tmp)
	checkout := filepath.Join(tmp, "checkout")
	output := filepath.Join(tmp, "osv-results.json")
	config := filepath.Join(tmp, "trusted-osv-scanner.toml")
	// Never honor ignore rules supplied by the repository being assessed.
	if err := os.WriteFile(config, nil, 0o600); err != nil {
		return Evidence{}, err
	}
	home := filepath.Join(tmp, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		return Evidence{}, err
	}
	env := toolEnvironment(home)
	clone := []string{git, "-c", "protocol.allow=never", "-c", "protocol.https.allow=always", "-c", "credential.helper=",
		"-c", "http.followRedirects=false", "-c", "core.hooksPath=" + os.DevNull, "-c", "submodule.recurse=false",
		"clone", "--quiet", "--depth", "1", "--single-branch", "--no-recurse-submodules", "--filter=blob:limit=20m",
		ref.NormalizedURL, checkout}
	result, err := runMonitored(clone, env, cloneTimeout, checkout, maxBytes, maxFiles, "repository clone")
	if _, timedOut := err.(timeoutError); timedOut {
		return Evidence{}, fetchError("repository clone exceeded %d seconds", int(cloneTimeout.Seconds()))
	}
	if err != nil {
		return Evidence{}, err
	}
	if result.code != 0 {
		return Evidence{}, toolFailure("repository clone failed", result)
	}
	fileCount, repositoryBytes, manifests, err := repositoryInventory(checkout, maxBytes, maxFiles)
	if err != nil {
		return Evidence{}, err
	}
	scan := []string{scanner, "scan", "source", "--format", "json", "--output-file", output, "--config", config,
		"--all-packages", "--no-resolve", "--recursive", checkout}
	result, err = runMonitored(scan, env, scanTimeout, output, maxOutput, 1, "osv-scanner output")
	if _, timedOut := err.(timeoutError); timedOut {
		return Evidence{}, fetchError("repository scan exceeded %d seconds", int(scanTimeout.Seconds()))
	}
	if err != nil {
		return Evidence{}, err
	}
	noPackages := result.code == 128
	if result.code != 0 && result.code != 1 && !noPackages {
		return Evidence{}, toolFailure("osv-scanner failed", result)
	}
	var content string
	info, statErr := os.Stat(output)
	switch {
	case statErr != nil && noPackages:
		content = `{"results": []}`
	case statErr != nil:
		return Evidence{}, fetchError("osv-scanner did not produce JSON output")
	case info.Size() > maxOutput:
		return Evidence{}, tooLarge("osv-scanner output exceeds the %d-byte limit", maxOutput)
	default:
		raw, err := os.ReadFile(output)
		if err != nil {
			return Evidence{}, fetchError("osv-scanner output could not be inspected")
		}
		content = string(raw)
	}
	var payload map[string]json.RawMessage
	if json.Unmarshal([]byte(content), &payload) != nil {
		return Evidence{}, fetchError("osv-scanner produced invalid JSON")
	}
	var results []json.RawMessage
	if json.Unmarshal(payload["results"], &results) != nil || results == nil {
		return Evidence{}, fetchError("osv-scanner JSON is missing its results list")
	}
	packages := 0
	for _, r := range results {
		var entry struct {
			Packages []json.RawMessage `json:"packages"`
		}
		if json.Unmarshal(r, &entry) == nil {
			packages += len(entry.Packages)
		}
	}
	commitCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	revParse := exec.CommandContext(commitCtx, git, "-C", checkout, "rev-parse", "HEAD")
	revParse.Env = env
	commit, _ := revParse.Output()

	status := "complete"
	switch {
	case len(manifests) == 0:
		status = "no_supported_manifest"
	case noPackages || packages == 0:
		status = "no_package_inventory"
	}
	warnings := []string{}
	if status != "complete" {
		warnings = append(warnings, "OSV-Scanner produced no supported package inventory; zero findings must not be "+
			"interpreted as a clean repository.")
	}
	return Evidence{Content: content, Format: "osv", Provenance: map[string]any{
		"provider": "local_osv_scanner", "repository": ref.Repository, "resolved_url": ref.NormalizedURL,
		"resolved_commit": strings.TrimSpace(string(commit)), "format": "osv", "scanner": "osv-scanner",
		"scanner_config": "trusted-empty-config", "file_count": fileCount, "repository_bytes": repositoryBytes,
		"manifests_detected": manifests, "component_count": packages, "coverage_status": status,
		"coverage": map[string]any{"status": status, "complete": status == "complete",
			"manifests_detected": len(manifests), "packages_detected": packages},
		"warnings": warnings, "retrieved_at": time.Now().UTC().Format(retrievedAtTimeFormat),
	}}, nil
}

func orDuration(v, fallback time.Duration) time.Duration {
	if v == 0 {
		return fallback
	}
	return v
}

func orInt64(v, fallback int64) int64 {
	if v == 0 {
		return fallback
	}
	return v
}
