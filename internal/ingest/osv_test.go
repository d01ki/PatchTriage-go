package ingest

import (
	"encoding/json"
	"testing"

	"github.com/d01ki/PatchTriage-go/internal/model"
)

func osvVuln(t *testing.T, doc string) OSVVuln {
	t.Helper()
	var v OSVVuln
	if err := json.Unmarshal([]byte(doc), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestSelectOSVFixedVersion(t *testing.T) {
	branches := osvVuln(t, `{"affected": [
		{"package": {"name": "widget", "ecosystem": "Maven"},
		 "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "99.0"}]}]},
		{"package": {"name": "widget", "ecosystem": "npm"},
		 "ranges": [{"type": "SEMVER", "events": [
			{"introduced": "0"}, {"fixed": "2.0.0"}, {"introduced": "3.0.0"}, {"fixed": "4.0.0"}]}]}]}`)
	rc := osvVuln(t, `{"affected": [{"package": {"name": "widget", "ecosystem": "npm"},
		"versions": ["2.0.6rc1"],
		"ranges": [
			{"type": "SEMVER", "events": [{"introduced": "1.9.0"}, {"fixed": "1.9.1"}]},
			{"type": "SEMVER", "events": [{"introduced": "2.0.0"}, {"fixed": "2.0.6"}]}]}]}`)
	ambiguous := osvVuln(t, `{"affected": [{"package": {"name": "widget", "ecosystem": "npm"},
		"versions": ["custom-build"],
		"ranges": [
			{"type": "SEMVER", "events": [{"introduced": "1.9.0"}, {"fixed": "1.9.1"}]},
			{"type": "SEMVER", "events": [{"introduced": "2.0.0"}, {"fixed": "2.0.6"}]}]}]}`)
	unqualified := osvVuln(t, `{"affected": [{"ranges": [{"type": "SEMVER",
		"events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]}`)
	mixed := osvVuln(t, `{"affected": [
		{"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]}]},
		{"package": {"name": "widget", "ecosystem": "npm"},
		 "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "3.0.0"}]}]}]}`)
	git := osvVuln(t, `{"affected": [{"package": {"name": "widget", "ecosystem": "npm"},
		"ranges": [{"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "abc123"}]}]}]}`)
	gitListed := osvVuln(t, `{"affected": [{"package": {"name": "widget", "ecosystem": "npm"},
		"versions": ["1.0.0"],
		"ranges": [{"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "abc123"}]}]}]}`)
	purl := osvVuln(t, `{"affected": [
		{"package": {"purl": "pkg:npm/other"}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": "9.0.0"}]}]},
		{"package": {"purl": "pkg:npm/%40scope/widget"}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}]}`)

	npm := func(version string) model.Package {
		return model.Package{Name: "widget", Ecosystem: "npm", Version: version}
	}
	cases := []struct {
		name string
		vuln OSVVuln
		pkg  model.Package
		want string
	}{
		{"first branch", branches, npm("1.5.0"), "2.0.0"},
		{"second branch", branches, npm("3.2.0"), "4.0.0"},
		{"rc is prerelease", rc, npm("2.0.6rc1"), "2.0.6"},
		{"ambiguous listed version", ambiguous, npm("custom-build"), ""},
		{"legacy unqualified record", unqualified, model.Package{Name: "lodash", Ecosystem: "npm", Version: "4.17.20"}, "4.17.21"},
		{"qualified entries hide unqualified", mixed, npm("0.5.0"), "3.0.0"},
		{"git range ignored", git, npm("1.0.0"), ""},
		{"git range with explicit version", gitListed, npm("1.0.0"), "abc123"},
		{"purl identity", purl, model.Package{Name: "widget", Purl: "pkg:npm/%40scope/widget@1.0.0", Version: "1.0.0"}, "2.0.0"},
		{"no installed version takes every fix", branches, npm(""), "2.0.0"},
	}
	for _, c := range cases {
		if got := SelectOSVFixedVersion(c.vuln, c.pkg); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func actionAdvisory(t *testing.T, ranges, versions string) OSVVuln {
	doc := `{"id": "X", "aliases": [], "affected": [{"package": {"name": "tj-actions/changed-files", "ecosystem": "GitHub Actions"}`
	if ranges != "" {
		doc += `, "ranges": [{"type": "ECOSYSTEM", "events": ` + ranges + `}]`
	}
	if versions != "" {
		doc += `, "versions": ` + versions
	}
	return osvVuln(t, doc+`}]}`)
}

func TestOSVAffects(t *testing.T) {
	action := model.Package{Name: "tj-actions/changed-files", Version: "45.0.9", Ecosystem: "githubactions",
		Purl: "pkg:githubactions/tj-actions/changed-files@45.0.9"}
	cases := []struct {
		name     string
		vuln     OSVVuln
		affected bool
	}{
		{"fixed above", actionAdvisory(t, `[{"introduced": "0"}, {"fixed": "46.0.1"}]`, ""), true},
		{"fixed below", actionAdvisory(t, `[{"introduced": "0"}, {"fixed": "45.0.8"}]`, ""), false},
		{"last affected inclusive", actionAdvisory(t, `[{"introduced": "45.0.0"}, {"last_affected": "45.0.9"}]`, ""), true},
		{"introduced later", actionAdvisory(t, `[{"introduced": "46.0.0"}]`, ""), false},
		{"listed with v prefix", actionAdvisory(t, "", `["v45.0.9"]`), true},
		{"never fixed", actionAdvisory(t, `[{"introduced": "45.0.0"}]`, ""), true},
		{"limit exclusive", actionAdvisory(t, `[{"introduced": "0"}, {"limit": "45.0.9"}]`, ""), false},
	}
	for _, c := range cases {
		if got := OSVAffects(c.vuln, action); got != c.affected {
			t.Errorf("%s: got %v, want %v", c.name, got, c.affected)
		}
	}
	if !OSVAffects(actionAdvisory(t, `[{"introduced": "0"}, {"fixed": "1.0.0"}]`, ""),
		model.Package{Name: "tj-actions/changed-files", Ecosystem: "githubactions"}) {
		t.Error("a package without a version cannot be ruled out")
	}
}

func TestOSVVulnDecodingIsLenient(t *testing.T) {
	v := osvVuln(t, `{"id": "X", "affected": [
		"not-an-object",
		{"package": {"name": "widget", "ecosystem": "npm"}, "versions": [1.0, "2.0"],
		 "ranges": ["bad", {"type": "semver", "events": ["bad", {"introduced": null}, {"fixed": 3}]}]}]}`)
	if len(v.Affected) != 1 || len(v.Affected[0].Ranges) != 1 || v.Affected[0].Versions[0] != "1.0" {
		t.Fatalf("lenient decode: %+v", v)
	}
	events := v.Affected[0].Ranges[0].Events
	if len(events) != 2 || !events[0].HasIntroduced || events[0].Introduced != "0" || events[1].Fixed != "3" {
		t.Errorf("events: %+v", events)
	}
}
