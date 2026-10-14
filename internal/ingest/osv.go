package ingest

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/d01ki/PatchTriage-go/internal/model"
)

// OSV records are untrusted third-party JSON. Like the Python
// implementation, decoding keeps every well-formed element and ignores
// elements of the wrong shape instead of rejecting the whole record.

// flexText renders a JSON scalar the way Python's str() would for the
// values OSV uses; null, false and "" are empty (Python falsy).
func flexText(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return ""
	}
	switch raw[0] {
	case '"':
		var s string
		_ = json.Unmarshal(raw, &s)
		return s
	case 'n', 'f', '{', '[':
		return ""
	case 't':
		return "True"
	}
	return string(raw)
}

func objectFields(raw []byte) (map[string]json.RawMessage, bool) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return nil, false
	}
	return fields, true
}

// objList decodes a JSON array keeping only object elements.
type objList[T any] []T

func (l *objList[T]) UnmarshalJSON(raw []byte) error {
	var items []json.RawMessage
	if json.Unmarshal(raw, &items) != nil {
		*l = nil
		return nil
	}
	for _, item := range items {
		if _, ok := objectFields(item); !ok {
			continue
		}
		var value T
		_ = json.Unmarshal(item, &value) // keep partially decoded objects
		*l = append(*l, value)
	}
	return nil
}

// strList decodes a JSON array of scalars into their str() renderings.
type strList []string

func (l *strList) UnmarshalJSON(raw []byte) error {
	var items []json.RawMessage
	if json.Unmarshal(raw, &items) != nil {
		*l = nil
		return nil
	}
	for _, item := range items {
		if text := flexText(item); text != "" || bytes.Equal(bytes.TrimSpace(item), []byte(`""`)) {
			*l = append(*l, text)
		}
	}
	return nil
}

// OSVPackage identifies the package of one affected entry.
type OSVPackage struct {
	Present               bool // a non-empty JSON object (a "qualified" entry)
	Name, Ecosystem, Purl string
}

func (p *OSVPackage) UnmarshalJSON(raw []byte) error {
	fields, ok := objectFields(raw)
	*p = OSVPackage{Present: ok && len(fields) > 0}
	if ok {
		p.Name, p.Ecosystem, p.Purl = flexText(fields["name"]), flexText(fields["ecosystem"]), flexText(fields["purl"])
	}
	return nil
}

// OSVEvent is one range event. Introduced is "0" when present but empty.
type OSVEvent struct {
	HasIntroduced                          bool
	Introduced, Fixed, LastAffected, Limit string
}

func (e *OSVEvent) UnmarshalJSON(raw []byte) error {
	fields, _ := objectFields(raw)
	_, has := fields["introduced"]
	*e = OSVEvent{HasIntroduced: has, Fixed: flexText(fields["fixed"]),
		LastAffected: flexText(fields["last_affected"]), Limit: flexText(fields["limit"])}
	if has {
		if e.Introduced = flexText(fields["introduced"]); e.Introduced == "" {
			e.Introduced = "0"
		}
	}
	return nil
}

// OSVRange is one affected range.
type OSVRange struct {
	Type   string            `json:"-"`
	Events objList[OSVEvent] `json:"events"`
}

func (r *OSVRange) UnmarshalJSON(raw []byte) error {
	fields, _ := objectFields(raw)
	*r = OSVRange{Type: strings.ToUpper(flexText(fields["type"]))}
	if events, ok := fields["events"]; ok {
		_ = r.Events.UnmarshalJSON(events)
	}
	return nil
}

// OSVSpecific carries the coarse severity label some databases add.
type OSVSpecific struct{ Severity string }

func (s *OSVSpecific) UnmarshalJSON(raw []byte) error {
	fields, _ := objectFields(raw)
	s.Severity = flexText(fields["severity"])
	return nil
}

// OSVAffected is one affected entry of an OSV record.
type OSVAffected struct {
	Package          *OSVPackage       `json:"package"`
	Versions         strList           `json:"versions"`
	Ranges           objList[OSVRange] `json:"ranges"`
	DatabaseSpecific OSVSpecific       `json:"database_specific"`
}

// OSVReference is one advisory reference.
type OSVReference struct {
	URL string `json:"-"`
}

func (r *OSVReference) UnmarshalJSON(raw []byte) error {
	fields, _ := objectFields(raw)
	r.URL = flexText(fields["url"])
	return nil
}

// OSVVuln is an OSV vulnerability record.
type OSVVuln struct {
	ID               string                `json:"id"`
	Aliases          strList               `json:"aliases"`
	Summary          string                `json:"summary"`
	Details          string                `json:"details"`
	Affected         objList[OSVAffected]  `json:"affected"`
	References       objList[OSVReference] `json:"references"`
	DatabaseSpecific OSVSpecific           `json:"database_specific"`
}

// OSVClient queries OSV.dev; its HTTP behavior lives in sbom.go.
type OSVClient struct {
	HTTP     *http.Client
	BaseURL  string
	CacheDir string
	// RegistryURLs overrides DefaultRegistryURLs per OSV ecosystem.
	RegistryURLs map[string]string
}

// purlIdentity is the version-independent, casefolded purl used for
// matching. PURL types are case-insensitive and OSV feeds occasionally vary
// only by case.
func purlIdentity(value string) string {
	typ, namespace, name, _ := model.ParsePurl(value)
	var parts []string
	for _, p := range []string{typ, namespace, name} {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return strings.ToLower(strings.Join(parts, "/"))
}

func qualified(a OSVAffected) bool { return a.Package != nil && a.Package.Present }

func hasQualified(entries []OSVAffected) bool {
	for _, a := range entries {
		if qualified(a) {
			return true
		}
	}
	return false
}

func affectedMatchesPackage(a OSVAffected, pkg model.Package, allowUnqualified bool) bool {
	if !qualified(a) {
		return allowUnqualified
	}
	targetName := pkg.Name
	targetEcosystem := model.NormalizeEcosystem(pkg.Ecosystem)
	targetPurl := purlIdentity(pkg.Purl)
	affectedName := a.Package.Name
	affectedEcosystem := model.NormalizeEcosystem(a.Package.Ecosystem)
	affectedPurl := purlIdentity(a.Package.Purl)

	if affectedPurl != "" && targetPurl != "" && affectedPurl != targetPurl {
		return false
	}
	if affectedName != "" && targetName != "" && !strings.EqualFold(affectedName, targetName) {
		return false
	}
	if affectedEcosystem != "" && targetEcosystem != "" && affectedEcosystem != targetEcosystem {
		return false
	}
	// If OSV supplies an identity field the input lacks, do not guess unless
	// another strong field (purl or name) established the match.
	if affectedName != "" && targetName == "" && !(affectedPurl != "" && targetPurl != "") {
		return false
	}
	// Ecosystem equality is a constraint, not package identity.
	return (affectedPurl != "" && targetPurl != "") || (affectedName != "" && targetName != "")
}

func rangeFixes(r OSVRange) []string {
	var fixes []string
	for _, e := range r.Events {
		if e.Fixed != "" {
			fixes = append(fixes, e.Fixed)
		}
	}
	return fixes
}

func rangeFixCandidates(r OSVRange, installed string, explicitlyAffected bool, ecosystem string) []string {
	if installed == "" {
		return rangeFixes(r)
	}
	// Git commit ranges are not comparable as package versions.
	if r.Type == "GIT" {
		if explicitlyAffected {
			return rangeFixes(r)
		}
		return nil
	}
	var candidates []string
	introduced, open := "0", true
	for _, e := range r.Events {
		if e.HasIntroduced {
			introduced, open = e.Introduced, true
			continue
		}
		if e.Fixed != "" {
			lowerOK := open && (introduced == "" || introduced == "0" ||
				model.CompareVersions(installed, introduced, ecosystem) >= 0)
			if lowerOK && model.CompareVersions(installed, e.Fixed, ecosystem) < 0 {
				candidates = append(candidates, e.Fixed)
			}
			// A fixed event closes the interval; a later introduced opens a new one.
			open = false
			continue
		}
		if e.LastAffected != "" || e.Limit != "" {
			open = false
		}
	}
	return candidates
}

func unique(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range values {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// SelectOSVFixedVersion chooses the applicable OSV fixed version for one
// package/version. Only matching affected entries are considered; for
// disjoint vulnerable intervals the fix closing the interval containing the
// installed version is selected.
func SelectOSVFixedVersion(v OSVVuln, pkg model.Package) string {
	allowUnqualified := !hasQualified(v.Affected)
	installed := pkg.Version
	ecosystem := model.NormalizeEcosystem(pkg.Ecosystem)
	var candidates []string
	for _, a := range v.Affected {
		if !affectedMatchesPackage(a, pkg, allowUnqualified) {
			continue
		}
		explicitlyAffected := false
		if installed != "" {
			for _, listed := range a.Versions {
				if listed == installed {
					explicitlyAffected = true
				}
			}
		}
		var found, entryFixes []string
		for _, r := range a.Ranges {
			entryFixes = append(entryFixes, rangeFixes(r)...)
			found = append(found, rangeFixCandidates(r, installed, explicitlyAffected, ecosystem)...)
		}
		// An explicit version list proves vulnerability but not which branch
		// applies: fall back only to a single unambiguous fix.
		if len(found) == 0 && explicitlyAffected {
			if fixes := unique(entryFixes); len(fixes) == 1 {
				found = fixes
			}
		}
		candidates = append(candidates, found...)
	}
	best := ""
	for i, c := range unique(candidates) {
		if i == 0 || model.CompareVersions(c, best, ecosystem) < 0 {
			best = c
		}
	}
	return best
}

// rangeAffects reports whether one ECOSYSTEM/SEMVER range covers installed.
func rangeAffects(r OSVRange, installed, ecosystem string) bool {
	introduced, open := "", false
	lowerOK := func() bool {
		return introduced == "" || introduced == "0" || model.CompareVersions(installed, introduced, ecosystem) >= 0
	}
	for _, e := range r.Events {
		if e.HasIntroduced {
			introduced, open = e.Introduced, true
			continue
		}
		if !open {
			continue
		}
		switch {
		case e.Fixed != "":
			if lowerOK() && model.CompareVersions(installed, e.Fixed, ecosystem) < 0 {
				return true
			}
		case e.LastAffected != "":
			if lowerOK() && model.CompareVersions(installed, e.LastAffected, ecosystem) <= 0 {
				return true
			}
		case e.Limit != "":
			if lowerOK() && model.CompareVersions(installed, e.Limit, ecosystem) < 0 {
				return true
			}
		}
		open = false
	}
	// An interval that is never closed affects every later version.
	return open && lowerOK()
}

// OSVAffects evaluates an OSV record's affected ranges for pkg locally, for
// ecosystems where OSV's query API cannot compare versions. Without an
// installed version nothing can be ruled out.
func OSVAffects(v OSVVuln, pkg model.Package) bool {
	installed := pkg.Version
	if installed == "" {
		_, _, _, installed = model.ParsePurl(pkg.Purl)
	}
	if installed == "" {
		return true
	}
	ecosystem := model.NormalizeEcosystem(pkg.Ecosystem)
	allowUnqualified := !hasQualified(v.Affected)
	bare := strings.TrimLeft(installed, "vV")
	for _, a := range v.Affected {
		if !affectedMatchesPackage(a, pkg, allowUnqualified) {
			continue
		}
		for _, listed := range a.Versions {
			if strings.TrimLeft(listed, "vV") == bare {
				return true
			}
		}
		for _, r := range a.Ranges {
			if r.Type != "GIT" && rangeAffects(r, installed, ecosystem) {
				return true
			}
		}
	}
	return false
}
