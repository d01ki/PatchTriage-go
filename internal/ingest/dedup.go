package ingest

// Dedup / correlation. Multiple scanners report the same real-world problem
// with different ids, severities and package spellings. Findings merge on
//
//	(canonical vuln id) x (ecosystem / namespace / package / installed version) x (asset)
//
// The canonical id prefers CVE over GHSA/DSA/... through the alias graph.
// Merging keeps the maximum severity / CVSS across scanners (conservative)
// and every reporting scanner.

import (
	"regexp"
	"sort"
	"strings"

	"github.com/d01ki/PatchTriage-go/internal/model"
)

var packageNormalizer = regexp.MustCompile(`[^a-z0-9]+`)

// normPackage: python_dateutil / python-dateutil / Python.Dateutil -> pythondateutil
func normPackage(name string) string {
	return packageNormalizer.ReplaceAllString(strings.ToLower(name), "")
}

// PackageIdentity returns the ecosystem, namespace, name and installed
// version identity. A purl is the most precise source; for scanners that
// omit it, common namespace-bearing spellings are interpreted.
func PackageIdentity(p model.Package) (ecosystem, namespace, name, version string) {
	purlType, namespace, purlName, _ := model.ParsePurl(p.Purl)
	ecosystemSource := p.Ecosystem
	if ecosystemSource == "" {
		ecosystemSource = purlType
	}
	ecosystem = model.NormalizeEcosystem(ecosystemSource)
	name = strings.TrimSpace(purlName)
	if purlName == "" {
		name = strings.TrimSpace(p.Name)
		rawName := strings.TrimSpace(p.Name)
		cut := func(sep string) {
			i := strings.LastIndex(rawName, sep)
			namespace, name = rawName[:i], rawName[i+1:]
		}
		switch {
		case ecosystem == "npm" && strings.HasPrefix(rawName, "@") && strings.Contains(rawName, "/"):
			cut("/")
		case ecosystem == "maven" && strings.Contains(rawName, ":"):
			cut(":")
		case (ecosystem == "golang" || ecosystem == "packagist") && strings.Contains(rawName, "/"):
			cut("/")
		}
	}
	return ecosystem, normPackage(namespace), normPackage(name), strings.TrimSpace(p.Version)
}

func isCVE(id string) bool { return strings.HasPrefix(strings.ToUpper(id), "CVE-") }

func canonicalID(r model.RawFinding, aliasMap map[string]string) string {
	ids := append([]string{r.VulnID}, r.Aliases...)
	for _, id := range ids {
		if isCVE(id) {
			return strings.ToUpper(id)
		}
	}
	// Non-CVE: an alias may already be linked to a CVE elsewhere.
	for _, id := range ids {
		if cve, ok := aliasMap[id]; ok {
			return cve
		}
	}
	return r.VulnID
}

type identity struct{ ecosystem, namespace, name, version string }

// orderedGroups is an insertion-ordered map of string keys to indexes.
type orderedGroups struct {
	keys   []string
	groups map[string][]int
}

func (o *orderedGroups) add(key string, index int) {
	if o.groups == nil {
		o.groups = map[string][]int{}
	}
	if _, ok := o.groups[key]; !ok {
		o.keys = append(o.keys, key)
	}
	o.groups[key] = append(o.groups[key], index)
}

func singleValue(values map[string]bool) (string, bool) {
	if len(values) != 1 {
		return "", false
	}
	for v := range values {
		return v, true
	}
	return "", false
}

// Dedup merges raw findings into one finding per vulnerability, component
// identity and asset, ordered by severity then CVSS (highest first).
func Dedup(raw []model.RawFinding) []*model.Finding {
	// Pass 1: alias -> CVE map across all findings (cross-scanner linking).
	aliasMap := map[string]string{}
	for _, r := range raw {
		ids := append([]string{r.VulnID}, r.Aliases...)
		var cves []string
		for _, id := range ids {
			if isCVE(id) {
				cves = append(cves, strings.ToUpper(id))
			}
		}
		if len(cves) > 0 {
			sort.Strings(cves)
			for _, id := range ids {
				aliasMap[id] = cves[0]
			}
		}
	}

	// Pass 2: fill a missing ecosystem/namespace only when the compatible
	// value is unambiguous; an empty field never bridges distinct packages.
	identities := make([]identity, len(raw))
	canonical := make([]string, len(raw))
	var base orderedGroups
	for i, r := range raw {
		e, ns, name, version := PackageIdentity(r.Package)
		identities[i] = identity{e, ns, name, version}
		canonical[i] = canonicalID(r, aliasMap)
		base.add(strings.Join([]string{canonical[i], name, version, r.Asset.Identifier}, "\x00"), i)
	}
	resolved := append([]identity(nil), identities...)
	for _, key := range base.keys {
		indexes := base.groups[key]
		ecosystems := map[string]bool{}
		for _, i := range indexes {
			if identities[i].ecosystem != "" {
				ecosystems[identities[i].ecosystem] = true
			}
		}
		if only, ok := singleValue(ecosystems); ok {
			for _, i := range indexes {
				if resolved[i].ecosystem == "" {
					resolved[i].ecosystem = only
				}
			}
		}
		var byEcosystem orderedGroups
		for _, i := range indexes {
			byEcosystem.add(resolved[i].ecosystem, i)
		}
		for _, e := range byEcosystem.keys {
			namespaces := map[string]bool{}
			for _, i := range byEcosystem.groups[e] {
				if resolved[i].namespace != "" {
					namespaces[resolved[i].namespace] = true
				}
			}
			if only, ok := singleValue(namespaces); ok {
				for _, i := range byEcosystem.groups[e] {
					if resolved[i].namespace == "" {
						resolved[i].namespace = only
					}
				}
			}
		}
	}

	// Pass 3: bucket by the complete component identity.
	var buckets orderedGroups
	for i, r := range raw {
		id := resolved[i]
		buckets.add(strings.Join([]string{canonical[i], id.ecosystem, id.namespace, id.name, id.version, r.Asset.Identifier}, "|"), i)
	}

	// Pass 4: merge each bucket.
	findings := make([]*model.Finding, 0, len(buckets.keys))
	for _, key := range buckets.keys {
		group := make([]model.RawFinding, 0, len(buckets.groups[key]))
		for _, i := range buckets.groups[key] {
			group = append(group, raw[i])
		}
		sort.SliceStable(group, func(a, b int) bool {
			return model.SeverityRank(group[a].Severity) > model.SeverityRank(group[b].Severity)
		})
		findings = append(findings, merge(key, group, aliasMap))
	}
	sort.SliceStable(findings, func(a, b int) bool {
		ra, rb := model.SeverityRank(findings[a].Severity), model.SeverityRank(findings[b].Severity)
		if ra != rb {
			return ra > rb
		}
		return scoreOrZero(findings[a].CVSSScore) > scoreOrZero(findings[b].CVSSScore)
	})
	return findings
}

func scoreOrZero(v *float64) float64 {
	if v == nil {
		return 0
	}
	return *v
}

func boolRank(b bool) int {
	if b {
		return 1
	}
	return 0
}

func merge(key string, group []model.RawFinding, aliasMap map[string]string) *model.Finding {
	head := group[0]
	vid := canonicalID(head, aliasMap)
	var ids, refs, candidates, scanners []string
	var cvss *float64
	fixedVersion, title, description := "", "", ""
	firstSeen := head.DetectedAt
	for _, r := range group {
		for _, id := range append([]string{r.VulnID}, r.Aliases...) {
			if strings.ToUpper(id) != vid {
				ids = append(ids, id)
			}
		}
		refs = append(refs, r.References...)
		if r.CVSSScore != nil {
			cvss = maxScore(cvss, *r.CVSSScore)
		}
		for _, c := range append([]string{r.Package.FixedVersion}, r.Package.FixedVersionCandidates...) {
			candidates = append(candidates, strings.TrimSpace(c))
		}
		if fixedVersion == "" {
			fixedVersion = r.Package.FixedVersion
		}
		if title == "" {
			title = r.Title
		}
		if len([]rune(r.Description)) > len([]rune(description)) {
			description = r.Description
		}
		scanners = append(scanners, r.SourceScanner)
		if r.DetectedAt.Before(firstSeen) {
			firstSeen = r.DetectedAt
		}
	}
	candidates = sortedNonEmpty(candidates)
	if fixedVersion == "" && len(candidates) > 0 {
		fixedVersion = candidates[0]
	}
	// The most descriptive component spelling: purl namespace, purl, ecosystem.
	component, best := group[0], -1
	for _, r := range group {
		_, ns, _, _ := model.ParsePurl(r.Package.Purl)
		rank := boolRank(ns != "")*4 + boolRank(r.Package.Purl != "")*2 + boolRank(model.NormalizeEcosystem(r.Package.Ecosystem) != "")
		if rank > best {
			component, best = r, rank
		}
	}
	pkg := component.Package
	pkg.FixedVersion = fixedVersion
	pkg.FixedVersionCandidates = nonNilStrings(candidates)
	refs = sortedNonEmpty(refs)
	if len(refs) > 20 {
		refs = refs[:20]
	}
	return &model.Finding{
		Key: key, VulnID: vid, Aliases: sortedSet(ids), Package: pkg, Asset: head.Asset,
		Severity: head.Severity, CVSSScore: cvss, Title: title, Description: description,
		References: nonNilStrings(refs), ReportedBy: sortedSet(scanners), FirstSeen: &firstSeen,
		SSVCInputs: map[string]string{},
	}
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
