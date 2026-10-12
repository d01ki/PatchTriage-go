package ingest

import (
	"strings"
	"testing"

	"github.com/d01ki/PatchTriage-go/internal/model"
)

func TestApplyContextFirstMatchingRule(t *testing.T) {
	path := writeTemp(t, "assets.yaml", "assets:\n  - match: 'web-frontend*'\n    criticality: critical\n"+
		"    internet_exposed: true\n    reachable: true\n    runtime_observed: true\n"+
		"    context_sources: [otel, falco]\n    system_exposure: open\n    automatable: yes\n"+
		"    mission_impact: mef_failure\n    safety_impact: marginal\n    publicly_exposed: no\n"+
		"    owner: platform-team\n    notes: customer checkout\n  - match: '*'\n    criticality: low\n")
	inventory, err := LoadInventory(path)
	if err != nil {
		t.Fatal(err)
	}
	web := &model.Finding{Asset: model.NewAsset("web-frontend:1.4")}
	other := &model.Finding{Asset: model.NewAsset("registry.local/batch/job:2")}
	matched, err := ApplyContext([]*model.Finding{web, other}, inventory)
	if err != nil || matched != 2 {
		t.Fatalf("matched %d, err %v", matched, err)
	}
	a := web.Asset
	if a.Criticality != "critical" || a.InternetExposed == nil || !*a.InternetExposed || !*a.Reachable ||
		!*a.RuntimeObserved || strings.Join(a.ContextSources, ",") != "otel,falco" || a.SystemExposure != "open" ||
		a.Automatable != "yes" || a.MissionImpact != "mef_failure" || a.SafetyImpact != "marginal" ||
		a.PubliclyExposed != "no" || a.Owner != "platform-team" || a.ContextNotes != "customer checkout" {
		t.Errorf("web asset = %+v", a)
	}
	// fnmatch "*" crosses "/" (unlike path.Match) and only the first rule applies.
	if other.Asset.Criticality != "low" || other.Asset.SystemExposure != "unknown" {
		t.Errorf("other asset = %+v", other.Asset)
	}
}

func TestApplyContextRejectsInvalidValues(t *testing.T) {
	for _, rule := range []string{"system_exposure: public", "internet_exposed: maybe", "mission_impact: huge"} {
		inventory, err := LoadInventory(writeTemp(t, "assets.yaml", "assets:\n  - match: '*'\n    "+rule+"\n"))
		if err != nil {
			t.Fatal(err)
		}
		_, err = ApplyContext([]*model.Finding{{Asset: model.NewAsset("x")}}, inventory)
		if err == nil || !strings.Contains(err.Error(), "inventory field") {
			t.Errorf("%s: err = %v", rule, err)
		}
	}
	if _, err := LoadInventory(writeTemp(t, "assets.yaml", "assets:\n  - criticality: low\n")); err == nil ||
		!strings.Contains(err.Error(), "missing 'match'") {
		t.Errorf("missing match: err = %v", err)
	}
	empty, err := LoadInventory(writeTemp(t, "assets.yaml", ""))
	if err != nil || len(empty) != 0 {
		t.Errorf("empty inventory: %v %v", empty, err)
	}
}

func TestFnmatch(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"web-frontend*", "web-frontend:1.4", true},
		{"*", "a/b:c", true},
		{"batch-?", "batch-1", true},
		{"batch-?", "batch-12", false},
		{"[ab]*", "b-x", true},
		{"[!ab]*", "b-x", false},
		{"web.*", "webXfoo", false},
		{"[", "[", true},
		{"Web*", "web", false},
	}
	for _, c := range cases {
		if got := fnmatch(c.name, c.pattern); got != c.want {
			t.Errorf("fnmatch(%q, %q) = %v, want %v", c.name, c.pattern, got, c.want)
		}
	}
}
