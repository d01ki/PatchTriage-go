package repository

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestMain lets the test binary stand in for git and osv-scanner when it is
// copied under those names (the scanner strips the environment, so the mode
// travels in the repository URL: the last path segment).
func TestMain(m *testing.M) {
	switch strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe") {
	case "git":
		os.Exit(fakeGit(os.Args[1:]))
	case "osv-scanner":
		os.Exit(fakeScanner(os.Args[1:]))
	}
	os.Exit(m.Run())
}

func fakeGit(args []string) int {
	if args[len(args)-1] == "HEAD" { // rev-parse HEAD
		fmt.Print("0123456789abcdef\n")
		return 0
	}
	url, checkout := args[len(args)-2], args[len(args)-1]
	mode := url[strings.LastIndex(url, "/")+1:]
	_ = os.MkdirAll(filepath.Join(checkout, ".git"), 0o755)
	_ = os.WriteFile(filepath.Join(checkout, ".git", "mode"), []byte(mode), 0o644)
	switch mode {
	case "nomanifest":
		_ = os.WriteFile(filepath.Join(checkout, "README.md"), []byte("hi"), 0o644)
	case "grow":
		for i := 0; i < 100; i++ {
			_ = os.WriteFile(filepath.Join(checkout, fmt.Sprintf("f%d", i)), []byte("x"), 0o644)
		}
		time.Sleep(30 * time.Second)
	case "fail":
		fmt.Fprint(os.Stderr, "fatal: repository not found")
		return 128
	default:
		_ = os.MkdirAll(filepath.Join(checkout, "web"), 0o755)
		_ = os.WriteFile(filepath.Join(checkout, "web", "package-lock.json"), []byte("{}"), 0o644)
	}
	return 0
}

func fakeScanner(args []string) int {
	var output string
	for i, a := range args {
		if a == "--output-file" {
			output = args[i+1]
		}
	}
	mode, _ := os.ReadFile(filepath.Join(args[len(args)-1], ".git", "mode"))
	write := func(s string) { _ = os.WriteFile(output, []byte(s), 0o644) }
	switch string(mode) {
	case "nopackages":
		return 128
	case "noresults":
		write(`{}`)
	case "nomanifest", "empty":
		write(`{"results": []}`)
	default:
		write(`{"results": [{"packages": [{"package": {"name": "a"}}, {"package": {"name": "b"}}]}]}`)
		return 1 // vulnerabilities found
	}
	return 0
}

func fakeTools(t *testing.T) (git, scanner string) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	suffix := ""
	if runtime.GOOS == "windows" {
		suffix = ".exe"
	}
	for _, name := range []string{"git", "osv-scanner"} {
		src, err := os.Open(self)
		if err != nil {
			t.Fatal(err)
		}
		dst, err := os.OpenFile(filepath.Join(dir, name+suffix), os.O_CREATE|os.O_WRONLY, 0o755)
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.Copy(dst, src)
		src.Close()
		dst.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "git"+suffix), filepath.Join(dir, "osv-scanner"+suffix)
}

func publicDNS(context.Context, string) ([]string, error) { return []string{"140.82.112.3"}, nil }

func scan(t *testing.T, s LocalScanner, url string) (Evidence, error) {
	t.Helper()
	ref, err := Normalize(url)
	if err != nil {
		t.Fatal(err)
	}
	return s.Scan(context.Background(), ref)
}

func TestPublicAddressCheckRejectsNonGlobalAnswers(t *testing.T) {
	for _, answers := range [][]string{{"10.0.0.5"}, {"140.82.112.3", "127.0.0.1"}, {"::1"}, {"fd00::1"},
		{"169.254.169.254"}, {"::ffff:192.168.1.1"}, {"100.64.0.1"}} {
		s := LocalScanner{Resolve: func(context.Context, string) ([]string, error) { return answers, nil }}
		if _, err := s.publicAddresses(context.Background(), "git.example"); err == nil ||
			!strings.Contains(err.Error(), "non-public") {
			t.Errorf("%v: err = %v", answers, err)
		}
	}
	s := LocalScanner{Resolve: func(context.Context, string) ([]string, error) { return []string{"2606:4700::1111", "1.1.1.1"}, nil }}
	if _, err := s.publicAddresses(context.Background(), "git.example"); err != nil {
		t.Errorf("public answers rejected: %v", err)
	}
}

func TestLocalScanUsesStaticToolsAndRecordsCommit(t *testing.T) {
	git, scanner := fakeTools(t)
	evidence, err := scan(t, LocalScanner{Git: git, Scanner: scanner, Resolve: publicDNS}, "https://git.example/acme/widget")
	if err != nil {
		t.Fatal(err)
	}
	p := evidence.Provenance
	if evidence.Format != "osv" || !strings.Contains(evidence.Content, `"results"`) || p["provider"] != "local_osv_scanner" ||
		p["resolved_commit"] != "0123456789abcdef" || p["coverage_status"] != "complete" || p["component_count"] != 2 ||
		strings.Join(p["manifests_detected"].([]string), ",") != "web/package-lock.json" || len(p["warnings"].([]string)) != 0 {
		t.Errorf("evidence = %+v", p)
	}
}

func TestLocalScanNeverCallsAnUncheckedRepositoryClean(t *testing.T) {
	git, scanner := fakeTools(t)
	s := LocalScanner{Git: git, Scanner: scanner, Resolve: publicDNS}
	for mode, want := range map[string]string{"nomanifest": "no_supported_manifest", "nopackages": "no_package_inventory",
		"empty": "no_package_inventory"} {
		evidence, err := scan(t, s, "https://git.example/acme/"+mode)
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		if evidence.Provenance["coverage_status"] != want || len(evidence.Provenance["warnings"].([]string)) != 1 {
			t.Errorf("%s: provenance = %v", mode, evidence.Provenance)
		}
	}
	if _, err := scan(t, s, "https://git.example/acme/noresults"); err == nil || !strings.Contains(err.Error(), "results list") {
		t.Errorf("missing results list: %v", err)
	}
	if _, err := scan(t, s, "https://git.example/acme/fail"); err == nil || !strings.Contains(err.Error(), "repository clone failed: fatal") {
		t.Errorf("clone failure: %v", err)
	}
}

func TestMonitoredCloneIsStoppedWhenTreeGrowsPastLimit(t *testing.T) {
	git, scanner := fakeTools(t)
	start := time.Now()
	_, err := scan(t, LocalScanner{Git: git, Scanner: scanner, Resolve: publicDNS, MaxFiles: 10}, "https://git.example/acme/grow")
	if e, ok := err.(*Error); !ok || e.Status != 413 || !strings.Contains(e.Message, "more than 10 files") {
		t.Errorf("err = %v", err)
	}
	if time.Since(start) > 15*time.Second {
		t.Errorf("the growing clone was not stopped promptly (%s)", time.Since(start))
	}
}

func TestMissingToolsAreReported(t *testing.T) {
	t.Setenv("PATH", "")
	_, err := scan(t, LocalScanner{Resolve: publicDNS}, "https://git.example/a/b")
	if err == nil || !strings.Contains(err.Error(), "requires git and osv-scanner") {
		t.Errorf("err = %v", err)
	}
}
