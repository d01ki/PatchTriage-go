package pipeline

// Remediation planning. Findings are the wrong unit of work: one package
// upgrade typically closes many findings. Findings are grouped into
// concrete actions ranked by the categorical SSVC Deployer outcome; no
// arithmetic risk score competes with or modifies that outcome.

import (
	"fmt"
	"sort"
	"strings"

	"github.com/d01ki/PatchTriage-go/internal/decision"
	"github.com/d01ki/PatchTriage-go/internal/ingest"
	"github.com/d01ki/PatchTriage-go/internal/model"
)

// Action is one concrete unit of remediation work.
type Action struct {
	ActionID                string   `json:"action_id"`
	Kind                    string   `json:"kind"` // upgrade | mitigate
	Summary                 string   `json:"summary"`
	Asset                   string   `json:"asset"`
	Package                 string   `json:"package"`
	Ecosystem               string   `json:"ecosystem"`
	PackageNamespace        string   `json:"package_namespace"`
	InstalledVersion        string   `json:"installed_version"`
	TargetVersion           string   `json:"target_version"`
	TargetVersionCandidates []string `json:"target_version_candidates"`
	FindingKeys             []string `json:"finding_keys"`
	CVEs                    []string `json:"cves"`
	TopPriority             string   `json:"top_priority"`
	DeadlineDays            int      `json:"deadline_days"` // the SSVC workflow target
	KEVCount                int      `json:"kev_count"`
	Rationales              []string `json:"rationales"`
	// Separate CISA BOD 26-04 view; the effective fields name their rule.
	BOD2604               map[string]any `json:"bod2604"`
	EffectiveDeadlineDays *int           `json:"effective_deadline_days"`
	EffectiveRule         string         `json:"effective_rule"`
	Obligations           []string       `json:"obligations"`
}

func versionCandidates(group []*model.Finding, ecosystem string) []string {
	var all []string
	for _, f := range group {
		for _, c := range append([]string{f.Package.FixedVersion}, f.Package.FixedVersionCandidates...) {
			all = append(all, strings.TrimSpace(c))
		}
	}
	candidates := ingest.SortedNonEmpty(all)
	sort.SliceStable(candidates, func(i, j int) bool {
		return model.CompareVersions(candidates[i], candidates[j], ecosystem) < 0
	})
	return candidates
}

func triageOf(f *model.Finding) (priority string, days int, rationale string) {
	if f.Triage == nil {
		return "P4", 90, ""
	}
	return f.Triage.Priority, f.Triage.SuggestedDeadlineDays, f.Triage.Rationale
}

// BuildPlan groups findings into actions and ranks them by SSVC timing.
func BuildPlan(findings []*model.Finding) []Action {
	type groupKey struct{ kind, asset, ecosystem, namespace, name, installed string }
	var order []groupKey
	groups := map[groupKey][]*model.Finding{}
	for _, f := range findings {
		ecosystem, namespace, name, installed := ingest.PackageIdentity(f.Package)
		kind := "mitigate"
		if f.Package.FixedVersion != "" {
			kind = "upgrade"
		}
		key := groupKey{kind, f.Asset.Identifier, ecosystem, namespace, name, installed}
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], f)
	}

	actions := make([]Action, 0, len(order))
	ordering := map[string][6]float64{}
	for _, key := range order {
		group := groups[key]
		pkg := group[0].Package.Name
		candidates := versionCandidates(group, key.ecosystem)
		target := ""
		if len(candidates) > 0 {
			target = candidates[len(candidates)-1]
		}
		top, deadline := "", 0
		var rationales, keys, cves []string
		kev := 0
		for n, f := range group {
			priority, days, rationale := triageOf(f)
			if n == 0 || decision.PriorityRank(priority) < decision.PriorityRank(top) {
				top = priority
			}
			if n == 0 || days < deadline {
				deadline = days
			}
			if len(rationales) < 3 {
				rationales = append(rationales, rationale)
			}
			keys = append(keys, f.Key)
			cves = append(cves, f.VulnID)
			if f.Enrichment.InCISAKEV {
				kev++
			}
		}
		summary := fmt.Sprintf("Upgrade %s to %s on %s", pkg, target, key.asset)
		if key.kind != "upgrade" {
			summary = fmt.Sprintf("No fixed version confirmed for %s on %s - investigate vendor guidance and apply mitigations", pkg, key.asset)
		}
		identity := strings.Join([]string{key.ecosystem, key.namespace, key.name, key.installed}, ":")
		id := key.kind + ":" + key.asset + ":" + identity
		var best [6]float64
		first := true
		for _, f := range group {
			if priority, _, _ := triageOf(f); priority != top {
				continue
			}
			if k := decision.SortKey(f); first || decision.CompareKeys(k, best) < 0 {
				best, first = k, false
			}
		}
		ordering[id] = best
		action := Action{ActionID: id, Kind: key.kind, Summary: summary, Asset: key.asset, Package: pkg,
			Ecosystem: key.ecosystem, PackageNamespace: key.namespace, InstalledVersion: key.installed,
			TargetVersion: target, TargetVersionCandidates: nonNil(candidates), FindingKeys: keys,
			CVEs: ingest.SortedNonEmpty(cves), TopPriority: top, DeadlineDays: deadline, KEVCount: kev,
			Rationales: rationales, Obligations: []string{}}
		if policy, ok := decision.PolicyForAction(group); ok {
			action.BOD2604, action.EffectiveDeadlineDays = policy.BOD2604, policy.EffectiveDeadlineDays
			action.EffectiveRule, action.Obligations = policy.EffectiveRule, policy.Obligations
		}
		actions = append(actions, action)
	}
	sort.SliceStable(actions, func(i, j int) bool {
		ri, rj := decision.PriorityRank(actions[i].TopPriority), decision.PriorityRank(actions[j].TopPriority)
		if ri != rj {
			return ri < rj
		}
		return decision.CompareKeys(ordering[actions[i].ActionID], ordering[actions[j].ActionID]) < 0
	})
	return actions
}

func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
