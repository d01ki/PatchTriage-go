package model

import (
	"encoding/json"
	"os"
	"testing"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		left, right, ecosystem string
		want                   int
	}{
		// tests/test_accuracy_core.py
		{"1.0-1", "1.0", "pypi", 1},
		{"1.0rc1", "1.0", "pypi", -1},
		{"1!1.0", "9.0", "pypi", 1},
		{"1.0-sp", "1.0", "maven", 1},
		{"1.0-rc1", "1.0", "maven", -1},
		{"1.0-final", "1.0", "maven", 0},
		{"1.0.1", "1.0", "maven", 1},
		// SemVer
		{"1.2.3", "1.10.0", "npm", -1},
		{"1.0.0-rc.1", "1.0.0", "npm", -1},
		{"1.0.0-alpha.2", "1.0.0-alpha.10", "npm", -1},
		{"v2.0.0", "1.9.9", "golang", 1},
		// PEP 440
		{"1.0.post1", "1.0", "pypi", 1},
		{"2.0.0a1", "2.0.0", "pypi", -1},
		{"1.0.dev1", "1.0a1", "pypi", -1},
		{"1.0", "1.0.0", "pypi", 0},
		{"1.0+local.1", "1.0", "pypi", 1},
		// Maven
		{"5.3.18", "5.3.17", "maven", 1},
		{"1.0-SNAPSHOT", "1.0", "maven", -1},
		{"1.0-beta", "1.0-alpha", "maven", 1},
		// Debian
		{"2.36-9+deb12u3", "2.36-9", "debian", 1},
		{"1:1.0", "2.0", "debian", 1},
		{"1.0~rc1", "1.0", "debian", -1},
		{"5.4.0-1", "5.4.0-1", "deb", 0},
		// Fallbacks
		{"2.0.6rc1", "2.0.6", "npm", -1},
		{"r10", "r9", "", 1},
	}
	for _, c := range cases {
		if got := CompareVersions(c.left, c.right, c.ecosystem); got != c.want {
			t.Errorf("CompareVersions(%q, %q, %q) = %d, want %d", c.left, c.right, c.ecosystem, got, c.want)
		}
	}
}

// TestCompareVersionsMatchesPython replays every pair recorded from the
// Python implementation (testdata/versions_python.json).
func TestCompareVersionsMatchesPython(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/versions_python.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows [][4]any
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		left, right, eco, want := row[0].(string), row[1].(string), row[2].(string), int(row[3].(float64))
		if got := CompareVersions(left, right, eco); got != want {
			t.Errorf("CompareVersions(%q, %q, %q) = %d, Python = %d", left, right, eco, got, want)
		}
	}
}
