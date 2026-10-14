package ingest

// Pick the concrete release to check when evidence gives only a constraint.
//
// Provider SBOMs record what a manifest declares rather than what is
// installed: GitHub's Dependency Graph lists "fastapi>=0.104.0" with no
// version and "uses: actions/checkout@v6" as "6.*.*". OSV only matches
// concrete versions, so each ecosystem's registry is asked for its releases
// and one is picked, with the basis recorded:
//
//   - a range with a lower bound (">=0.104.0", "^1.2.3", "~=2.0") is checked
//     at the oldest release it permits -- the range still allows installing
//     it, and a vulnerable floor is exactly what "raise the minimum version"
//     remediates;
//   - a floating ref ("6.*.*", "1.x", "==1.2.*") or a bare upper bound is
//     checked at the newest matching release, which is what actually runs;
//   - no constraint at all is checked at the newest release.
//
// None of these is necessarily what a deployment runs, so the caller labels
// the version as inferred and keeps coverage incomplete.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/d01ki/PatchTriage-go/internal/enrich"
	"github.com/d01ki/PatchTriage-go/internal/model"
)

const (
	registryTimeout    = 15 * time.Second
	registryWorkers    = 4
	maxRegistryLookups = 200
)

var maxRegistryBytes = 32 * 1024 * 1024 // a variable so tests can lower it

// resolutionError is a constraint that cannot be evaluated or that nothing
// satisfies.
type resolutionError string

func (e resolutionError) Error() string { return string(e) }

type release struct {
	version string // the value OSV is queried with
	parsed  model.PyVersion
}

func parseRelease(value string) (model.PyVersion, bool) {
	return model.ParsePyVersion(strings.TrimLeft(strings.TrimSpace(value), "vV"))
}

func releasesOf(values []string, stripV bool) []release {
	var out []release
	for _, value := range values {
		value = strings.TrimSpace(value)
		parsed, ok := parseRelease(value)
		if !ok || value == "" {
			continue
		}
		if stripV {
			value = strings.TrimLeft(value, "vV")
		}
		out = append(out, release{value, parsed})
	}
	return out
}

func canonicalDigits(s string) string {
	if s = strings.TrimLeft(s, "0"); s == "" {
		return "0"
	}
	return s
}

// ------------------------------------------------------------ constraints

func isWildcardPart(p string) bool { return p == "*" || p == "x" || p == "X" }

// wildcardPrefix turns "6.*.*" / "6.x" into the release prefix ["6"]; ok is
// false when constraint is not a wildcard.
func wildcardPrefix(constraint string) (prefix []string, ok bool, err error) {
	parts := strings.Split(strings.TrimLeft(strings.TrimSpace(constraint), "vV"), ".")
	prefix = []string{}
	for i, p := range parts {
		if isWildcardPart(p) {
			for _, rest := range parts[i:] {
				if !isWildcardPart(rest) {
					return nil, false, resolutionError(fmt.Sprintf("unsupported wildcard '%s'", constraint))
				}
			}
			return prefix, true, nil
		}
		if !isDigits(p) {
			return nil, false, nil
		}
		prefix = append(prefix, canonicalDigits(p))
	}
	return nil, false, nil
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

var caretTildePattern = regexp.MustCompile(`^([\^~])\s*v?(\d+)(?:\.(\d+))?(?:\.(\d+))?$`)

// caretTilde rewrites npm/Cargo/Composer "^1.2.3" and "~1.2.3" as PEP 440
// ranges.
func caretTilde(constraint string) (string, bool) {
	m := caretTildePattern.FindStringSubmatch(strings.TrimSpace(constraint))
	if m == nil {
		return "", false
	}
	num := func(s string) int {
		n, _ := strconv.Atoi(s)
		return n
	}
	x, y, z := num(m[2]), num(m[3]), num(m[4])
	hasMinor, hasPatch := m[3] != "", m[4] != ""
	var upper string
	switch {
	case m[1] == "~" && hasMinor: // ~1.2.3 / ~1.2 -> <1.3
		upper = fmt.Sprintf("%d.%d", x, y+1)
	case m[1] == "~": // ~1 -> <2
		upper = fmt.Sprintf("%d", x+1)
	case x > 0 || !hasMinor: // ^1.2.3 -> <2 ; ^0 -> <1
		upper = fmt.Sprintf("%d", x+1)
	case y > 0 || !hasPatch: // ^0.2.3 -> <0.3 ; ^0.0 -> <0.1
		upper = fmt.Sprintf("0.%d", y+1)
	default: // ^0.0.3 -> <0.0.4
		upper = fmt.Sprintf("0.0.%d", z+1)
	}
	return fmt.Sprintf(">=%d.%d.%d,<%s", x, y, z, upper), true
}

// One PEP 440 specifier (packaging.specifiers.Specifier).
type specifier struct {
	op, version string
	parsed      model.PyVersion // unset for "===" and wildcards
	epoch       string          // wildcard / "~=" prefix
	prefix      []string
	wildcard    bool
}

const (
	pepPre  = `(?:[-_.]?(?:alpha|beta|preview|pre|a|b|c|rc)[-_.]?[0-9]*)?`
	pepPost = `(?:(?:-[0-9]+)|(?:[-_.]?(?:post|rev|r)[-_.]?[0-9]*))?`
	pepDev  = `(?:[-_.]?dev[-_.]?[0-9]*)?`
	pepBase = `v?(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*`
)

var (
	specOperator  = regexp.MustCompile(`^\s*(~=|===|==|!=|<=|>=|<|>)\s*(.*?)\s*$`)
	specArbitrary = regexp.MustCompile(`^[^\s;)]*$`)
	specEquality  = regexp.MustCompile(`(?i)^` + pepBase + `(?:\.\*|` + pepPre + pepPost + pepDev +
		`(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?)$`)
	specCompatible = regexp.MustCompile(`(?i)^v?(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)+` + pepPre + pepPost + pepDev + `$`)
	specOrdered    = regexp.MustCompile(`(?i)^` + pepBase + pepPre + pepPost + pepDev + `$`)
	releaseDigits  = regexp.MustCompile(`^v?(?:([0-9]+)!)?([0-9]+(?:\.[0-9]+)*)`)
)

func parseSpecifier(text string) (specifier, bool) {
	m := specOperator.FindStringSubmatch(text)
	if m == nil {
		return specifier{}, false
	}
	s := specifier{op: m[1], version: m[2]}
	switch s.op {
	case "===":
		return s, specArbitrary.MatchString(s.version)
	case "==", "!=":
		if !specEquality.MatchString(s.version) {
			return specifier{}, false
		}
		if strings.HasSuffix(s.version, ".*") {
			s.wildcard = true
			s.epoch, s.prefix = splitRelease(strings.TrimSuffix(s.version, ".*"))
			return s, true
		}
	case "~=":
		if !specCompatible.MatchString(s.version) {
			return specifier{}, false
		}
		s.epoch, s.prefix = splitRelease(s.version)
		s.prefix = s.prefix[:len(s.prefix)-1]
	default:
		if !specOrdered.MatchString(s.version) {
			return specifier{}, false
		}
	}
	parsed, ok := model.ParsePyVersion(s.version)
	s.parsed = parsed
	return s, ok
}

// splitRelease is the epoch and release digits as written (packaging
// compares the specifier's text against the canonical candidate).
func splitRelease(version string) (string, []string) {
	m := releaseDigits.FindStringSubmatch(version)
	epoch := m[1]
	if epoch == "" {
		epoch = "0"
	}
	return epoch, strings.Split(m[2], ".")
}

// prefixMatch is packaging's "==V.*" test: the candidate's release, padded
// with zeros, starts with prefix.
func prefixMatch(v model.PyVersion, epoch string, prefix []string) bool {
	if v.Epoch() != epoch {
		return false
	}
	rel := v.Release()
	for i, want := range prefix {
		got := "0"
		if i < len(rel) {
			got = rel[i]
		}
		if got != want {
			return false
		}
	}
	return true
}

func (s specifier) contains(v model.PyVersion, text string) bool {
	switch s.op {
	case "===":
		return strings.EqualFold(text, s.version)
	case "==", "!=":
		var equal bool
		switch {
		case s.wildcard:
			equal = prefixMatch(v.Public(), s.epoch, s.prefix)
		case s.parsed.HasLocal():
			equal = v.Compare(s.parsed) == 0
		default:
			equal = v.Public().Compare(s.parsed) == 0
		}
		return equal == (s.op == "==")
	case "~=":
		return v.Public().Compare(s.parsed) >= 0 && prefixMatch(v.Public(), s.epoch, s.prefix)
	case "<=":
		return v.Public().Compare(s.parsed) <= 0
	case ">=":
		return v.Public().Compare(s.parsed) >= 0
	case "<":
		if v.Compare(s.parsed) >= 0 {
			return false
		}
		return s.parsed.IsPrerelease() || !v.IsPrerelease() || v.Base().Compare(s.parsed.Base()) != 0
	case ">":
		if v.Compare(s.parsed) <= 0 {
			return false
		}
		if !s.parsed.IsPostrelease() && v.IsPostrelease() && v.Base().Compare(s.parsed.Base()) == 0 {
			return false
		}
		return !v.HasLocal() || v.Base().Compare(s.parsed.Base()) != 0
	}
	return false
}

// floor reports whether the specifier sets a lower bound.
func (s specifier) floor() bool {
	switch s.op {
	case ">=", ">", "~=", "===":
		return true
	case "==":
		return !strings.Contains(s.version, "*")
	}
	return false
}

var (
	spaceBeforeOperator = regexp.MustCompile(`([\d*])\s+([<>=!~])`)
	singleEquals        = regexp.MustCompile(`(^|,)\s*=\s*(\d)`)
	vAfterOperator      = regexp.MustCompile(`([<>=])\s*v(\d)`)
)

// specifiers parses a constraint as a PEP 440 specifier set, accepting npm's
// space-separated ranges, "= 1.2" and caret/tilde ranges.
func specifiers(constraint string) ([]specifier, error) {
	text := strings.TrimSpace(constraint)
	if strings.Contains(text, "||") {
		return nil, resolutionError(fmt.Sprintf("unsupported alternative range '%s'", constraint))
	}
	converted, ok := caretTilde(text)
	if !ok {
		text = spaceBeforeOperator.ReplaceAllString(text, "$1,$2")
		text = singleEquals.ReplaceAllString(text, "$1==$2")
		text = vAfterOperator.ReplaceAllString(text, "$1$2")
		converted = strings.ReplaceAll(text, " ", "")
	}
	var out []specifier
	for _, piece := range strings.Split(converted, ",") {
		if piece = strings.TrimSpace(piece); piece == "" {
			continue
		}
		s, ok := parseSpecifier(piece)
		if !ok {
			return nil, resolutionError(fmt.Sprintf("constraint '%s' is not a version range", constraint))
		}
		out = append(out, s)
	}
	return out, nil
}

// newest prefers the full release over a floating major tag ("v6" equals
// 6.0.0); the first of equals wins, as Python's max does.
func newest(matching []release) release {
	best := matching[0]
	for _, r := range matching[1:] {
		c := r.parsed.Compare(best.parsed)
		if c > 0 || (c == 0 && strings.Count(r.version, ".") > strings.Count(best.version, ".")) {
			best = r
		}
	}
	return best
}

func oldest(matching []release) release {
	best := matching[0]
	for _, r := range matching[1:] {
		if r.parsed.Compare(best.parsed) < 0 {
			best = r
		}
	}
	return best
}

// chooseRelease returns the release to check for constraint and the basis
// for choosing it. preferred is the registry's own "latest" pointer (npm
// dist-tag), honoured only without a constraint because that is what a plain
// install selects even when a newer backport exists.
func chooseRelease(releases []release, constraint, preferred string) (release, string, error) {
	var stable []release
	for _, r := range releases {
		if !r.parsed.IsPrerelease() {
			stable = append(stable, r)
		}
	}
	constraint = strings.TrimSpace(constraint)
	if constraint == "" {
		if len(stable) == 0 {
			return release{}, "", resolutionError("the registry lists no stable release")
		}
		for _, r := range stable {
			if r.version == preferred {
				return r, "newest release", nil
			}
		}
		return newest(stable), "newest release", nil
	}
	prefix, isWildcard, err := wildcardPrefix(constraint)
	if err != nil {
		return release{}, "", err
	}
	var matching []release
	floor := false
	if isWildcard {
		for _, r := range stable {
			rel := r.parsed.Release()
			if len(rel) >= len(prefix) && strings.Join(rel[:len(prefix)], ".") == strings.Join(prefix, ".") {
				matching = append(matching, r)
			}
		}
	} else {
		specs, err := specifiers(constraint)
		if err != nil {
			return release{}, "", err
		}
		for _, r := range stable {
			ok := true
			for _, s := range specs {
				if !s.contains(r.parsed, r.version) {
					ok = false
					break
				}
			}
			if ok {
				matching = append(matching, r)
			}
		}
		for _, s := range specs {
			floor = floor || s.floor()
		}
	}
	if len(matching) == 0 {
		return release{}, "", resolutionError(fmt.Sprintf("no stable release satisfies '%s'", constraint))
	}
	if floor {
		return oldest(matching), "oldest release permitted by " + constraint, nil
	}
	return newest(matching), "newest release matching " + constraint, nil
}

// ------------------------------------------------------------ registries

// RegistryLabels names each registry in recorded evidence.
var RegistryLabels = map[string]string{
	"PyPI": "PyPI", "npm": "npm", "crates.io": "crates.io", "RubyGems": "RubyGems",
	"NuGet": "NuGet", "Go": "Go module proxy", "Packagist": "Packagist", "GitHub Actions": "GitHub tags",
}

// DefaultRegistryURLs are the registry base URLs; tests point them at
// local servers through OSVClient.RegistryURLs.
var DefaultRegistryURLs = map[string]string{
	"PyPI": "https://pypi.org", "npm": "https://registry.npmjs.org", "crates.io": "https://crates.io",
	"RubyGems": "https://rubygems.org", "NuGet": "https://api.nuget.org", "Go": "https://proxy.golang.org",
	"Packagist": "https://repo.packagist.org", "GitHub Actions": "https://api.github.com",
}

type registryClient struct {
	http *http.Client
	urls map[string]string
}

func (c registryClient) base(ecosystem string) string {
	if u, ok := c.urls[ecosystem]; ok {
		return u
	}
	return DefaultRegistryURLs[ecosystem]
}

func (c registryClient) getBytes(ctx context.Context, url string, headers map[string]string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, registryTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "patchtriage")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := enrich.StatusError(resp); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxRegistryBytes)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxRegistryBytes {
		return nil, resolutionError(fmt.Sprintf("registry response exceeded %d bytes", maxRegistryBytes))
	}
	return raw, nil
}

// PyQuote is urllib.parse.quote: unreserved characters and safe stay as is.
func PyQuote(s, safe string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
			strings.IndexByte("_.-~", c) >= 0 || strings.IndexByte(safe, c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func (c registryClient) getJSON(ctx context.Context, url string, headers map[string]string) (json.RawMessage, error) {
	raw, err := c.getBytes(ctx, url, headers)
	if err != nil {
		return nil, err
	}
	if !json.Valid(raw) {
		return nil, fmt.Errorf("registry returned invalid JSON")
	}
	return raw, nil
}

// shapeError is a registry response of an unexpected JSON shape.
func shapeError(what string) error { return fmt.Errorf("unexpected %s response shape", what) }

func (c registryClient) pypi(ctx context.Context, name string) ([]release, string, error) {
	raw, err := c.getJSON(ctx, c.base("PyPI")+"/pypi/"+PyQuote(name, "")+"/json", nil)
	if err != nil {
		return nil, "", err
	}
	fields, ok := objectFields(raw)
	if !ok {
		return nil, "", shapeError("PyPI")
	}
	order, files := enrich.OrderedKeys(fields["releases"])
	var live []string
	for _, version := range order {
		var entries []json.RawMessage
		if json.Unmarshal(files[version], &entries) != nil || len(entries) == 0 {
			continue
		}
		allYanked := true
		for _, entry := range entries {
			var f struct {
				Yanked any `json:"yanked"`
			}
			if json.Unmarshal(entry, &f) != nil || !truthy(f.Yanked) {
				allYanked = false
				break
			}
		}
		if !allYanked {
			live = append(live, version)
		}
	}
	return releasesOf(live, false), "", nil
}

// truthy is Python's bool() for a decoded JSON value.
func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case float64:
		return x != 0
	case string:
		return x != ""
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

func (c registryClient) npm(ctx context.Context, name string) ([]release, string, error) {
	raw, err := c.getJSON(ctx, c.base("npm")+"/"+PyQuote(name, "@/"),
		map[string]string{"Accept": "application/vnd.npm.install-v1+json"})
	if err != nil {
		return nil, "", err
	}
	fields, ok := objectFields(raw)
	if !ok {
		return nil, "", shapeError("npm")
	}
	versions, _ := enrich.OrderedKeys(fields["versions"])
	tags, _ := objectFields(fields["dist-tags"])
	return releasesOf(versions, false), flexText(tags["latest"]), nil
}

// textsOf reads field from each object of a JSON list, skipping entries
// where skip is true.
func textsOf(raw json.RawMessage, field string, skip func(map[string]json.RawMessage) bool) ([]string, bool) {
	var items []json.RawMessage
	if json.Unmarshal(raw, &items) != nil {
		return nil, false
	}
	var out []string
	for _, item := range items {
		if f, ok := objectFields(item); ok && (skip == nil || !skip(f)) {
			out = append(out, flexText(f[field]))
		}
	}
	return out, true
}

func flagSet(f map[string]json.RawMessage, key string) bool {
	var v any
	_ = json.Unmarshal(f[key], &v)
	return truthy(v)
}

func (c registryClient) crates(ctx context.Context, name string) ([]release, string, error) {
	raw, err := c.getJSON(ctx, c.base("crates.io")+"/api/v1/crates/"+PyQuote(name, ""),
		map[string]string{"User-Agent": "patchtriage (version resolution)"})
	if err != nil {
		return nil, "", err
	}
	fields, ok := objectFields(raw)
	if !ok {
		return nil, "", shapeError("crates.io")
	}
	values, _ := textsOf(fields["versions"], "num", func(f map[string]json.RawMessage) bool { return flagSet(f, "yanked") })
	return releasesOf(values, false), "", nil
}

func (c registryClient) rubygems(ctx context.Context, name string) ([]release, string, error) {
	raw, err := c.getJSON(ctx, c.base("RubyGems")+"/api/v1/versions/"+PyQuote(name, "")+".json", nil)
	if err != nil {
		return nil, "", err
	}
	values, ok := textsOf(raw, "number", func(f map[string]json.RawMessage) bool { return flagSet(f, "prerelease") })
	if !ok {
		return nil, "", shapeError("RubyGems")
	}
	return releasesOf(values, false), "", nil
}

func (c registryClient) nuget(ctx context.Context, name string) ([]release, string, error) {
	raw, err := c.getJSON(ctx, c.base("NuGet")+"/v3-flatcontainer/"+PyQuote(strings.ToLower(name), "")+"/index.json", nil)
	if err != nil {
		return nil, "", err
	}
	var data struct {
		Versions []json.RawMessage `json:"versions"`
	}
	if json.Unmarshal(raw, &data) != nil {
		return nil, "", shapeError("NuGet")
	}
	var values []string
	for _, v := range data.Versions {
		values = append(values, flexText(v))
	}
	return releasesOf(values, false), "", nil
}

var upperASCII = regexp.MustCompile(`[A-Z]`)

func (c registryClient) goProxy(ctx context.Context, name string) ([]release, string, error) {
	// The module proxy escapes capitals as "!" + lowercase.
	escaped := upperASCII.ReplaceAllStringFunc(name, func(s string) string { return "!" + strings.ToLower(s) })
	raw, err := c.getBytes(ctx, c.base("Go")+"/"+PyQuote(escaped, "/!")+"/@v/list", nil)
	if err != nil {
		return nil, "", err
	}
	return releasesOf(strings.Fields(strings.ToValidUTF8(string(raw), "�")), true), "", nil
}

func (c registryClient) packagist(ctx context.Context, name string) ([]release, string, error) {
	raw, err := c.getJSON(ctx, c.base("Packagist")+"/p2/"+PyQuote(name, "/")+".json", nil)
	if err != nil {
		return nil, "", err
	}
	fields, ok := objectFields(raw)
	if !ok {
		return nil, "", shapeError("Packagist")
	}
	packages, _ := objectFields(fields["packages"])
	values, _ := textsOf(packages[name], "version", nil)
	return releasesOf(values, false), "", nil
}

func (c registryClient) githubActions(ctx context.Context, name string) ([]release, string, error) {
	// "owner/repo/path/to/action" is versioned by the repository's tags.
	parts := strings.Split(name, "/")
	ownerRepo := strings.Join(parts[:min(2, len(parts))], "/")
	// Deliberately unauthenticated: the action name comes from untrusted SBOM
	// content, and a service token could reveal private repositories' tags.
	raw, err := c.getJSON(ctx, c.base("GitHub Actions")+"/repos/"+PyQuote(ownerRepo, "/")+"/git/matching-refs/tags",
		map[string]string{"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
	if err != nil {
		return nil, "", err
	}
	refs, ok := textsOf(raw, "ref", nil)
	if !ok {
		return nil, "", shapeError("GitHub")
	}
	for i, ref := range refs {
		refs[i] = strings.TrimPrefix(ref, "refs/tags/")
	}
	// OSV records GitHub Actions versions without the tag's "v".
	return releasesOf(refs, true), "", nil
}

func (c registryClient) fetch(ctx context.Context, ecosystem, name string) ([]release, string, error) {
	switch ecosystem {
	case "PyPI":
		return c.pypi(ctx, name)
	case "npm":
		return c.npm(ctx, name)
	case "crates.io":
		return c.crates(ctx, name)
	case "RubyGems":
		return c.rubygems(ctx, name)
	case "NuGet":
		return c.nuget(ctx, name)
	case "Go":
		return c.goProxy(ctx, name)
	case "Packagist":
		return c.packagist(ctx, name)
	case "GitHub Actions":
		return c.githubActions(ctx, name)
	}
	return nil, "", fmt.Errorf("no registry for %s", ecosystem)
}

// ------------------------------------------------------------ batch

type resolveRequest struct {
	index      int
	ecosystem  string // OSV ecosystem name
	name       string
	constraint string // "" when the SBOM gave no version at all
}

type resolution struct {
	request             resolveRequest
	version, basis, err string
}

// resolveVersions resolves each request concurrently; failures stay per
// component.
func resolveVersions(ctx context.Context, requests []resolveRequest, c registryClient) ([]resolution, []string) {
	var errs []string
	if len(requests) > maxRegistryLookups {
		errs = append(errs, fmt.Sprintf("%d component(s) exceeded the registry lookup limit and stay unchecked",
			len(requests)-maxRegistryLookups))
		requests = requests[:maxRegistryLookups]
	}
	results := make([]resolution, len(requests))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for range min(registryWorkers, len(requests)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				results[i] = resolveOne(ctx, requests[i], c)
			}
		}()
	}
	for i := range requests {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	for _, r := range results {
		if r.err != "" {
			errs = append(errs, r.err)
		}
	}
	return results, errs
}

func resolveOne(ctx context.Context, r resolveRequest, c registryClient) resolution {
	label := r.constraint
	if label == "" {
		label = "no version"
	}
	fail := func(err error) resolution {
		if _, ok := err.(resolutionError); ok {
			return resolution{request: r, err: fmt.Sprintf("%s (%s): %s", r.name, label, err)}
		}
		return resolution{request: r, err: fmt.Sprintf("%s (%s): %s lookup failed: %s", r.name, label, RegistryLabels[r.ecosystem], err)}
	}
	// Reject refs such as "release/v1" before touching the network.
	if r.constraint != "" {
		_, isWildcard, err := wildcardPrefix(r.constraint)
		if err != nil {
			return fail(err)
		}
		if !isWildcard {
			if _, err := specifiers(r.constraint); err != nil {
				return fail(err)
			}
		}
	}
	releases, preferred, err := c.fetch(ctx, r.ecosystem, r.name)
	if err != nil {
		return fail(err)
	}
	chosen, basis, err := chooseRelease(releases, r.constraint, preferred)
	if err != nil {
		return fail(err)
	}
	return resolution{request: r, version: chosen.version, basis: basis}
}

// ------------------------------------------------------------ manifests

// requirementsPattern matches requirements.txt, requirements-dev.in,
// dev-requirements.txt and any .txt under a requirements/ directory.
var requirementsPattern = regexp.MustCompile(`(?i)(^|/)([^/]*requirements[^/]*\.(txt|in)|requirements/[^/]+\.txt)$`)

// IsManifest reports whether path is a manifest whose declared ranges
// GitHub's SBOM drops.
func IsManifest(path string) bool {
	for _, part := range strings.Split(path, "/") {
		if part == "node_modules" || part == "vendor" || part == "site-packages" {
			return false
		}
	}
	base := path[strings.LastIndex(path, "/")+1:]
	return base == "pyproject.toml" || base == "package.json" || requirementsPattern.MatchString(path)
}

var pypiSeparators = regexp.MustCompile(`[-_.]+`)

// PyPIKey is the PEP 503 normalized project name.
func PyPIKey(name string) string { return strings.ToLower(pypiSeparators.ReplaceAllString(name, "-")) }

var (
	requirementName = regexp.MustCompile(`(?i)^([A-Z0-9][A-Z0-9._-]*[A-Z0-9]|[A-Z0-9])`)
	extrasList      = regexp.MustCompile(`(?i)^\[\s*(?:[A-Z0-9][A-Z0-9._-]*(?:\s*,\s*[A-Z0-9][A-Z0-9._-]*)*)?\s*\]`)
)

// parseRequirement reads a PEP 508 requirement as packaging.Requirement
// does and returns its name and str(requirement.specifier): the specifiers
// sorted and comma-joined.
func parseRequirement(line string) (name, spec string, ok bool) {
	line = strings.TrimSpace(line)
	name = requirementName.FindString(line)
	if name == "" {
		return "", "", false
	}
	rest := strings.TrimSpace(line[len(name):])
	if strings.HasPrefix(rest, "[") {
		extras := extrasList.FindString(rest)
		if extras == "" {
			return "", "", false
		}
		rest = strings.TrimSpace(rest[len(extras):])
	}
	if strings.HasPrefix(rest, "@") {
		return name, "", true
	}
	if before, marker, found := strings.Cut(rest, ";"); found {
		if strings.TrimSpace(marker) == "" {
			return "", "", false // packaging requires a marker after ";"
		}
		rest = before
	}
	rest = strings.TrimSpace(rest)
	if strings.HasPrefix(rest, "(") && strings.HasSuffix(rest, ")") {
		rest = strings.TrimSpace(rest[1 : len(rest)-1])
	}
	if rest == "" {
		return name, "", true
	}
	pieces := strings.Split(rest, ",")
	if len(pieces) > 1 && strings.TrimSpace(pieces[len(pieces)-1]) == "" {
		pieces = pieces[:len(pieces)-1] // packaging accepts a trailing comma
	}
	var specs []string
	for _, piece := range pieces {
		s, valid := parseSpecifier(piece)
		if !valid {
			return "", "", false
		}
		specs = append(specs, s.op+s.version)
	}
	sort.Strings(specs)
	return name, strings.Join(specs, ","), true
}

type nameSpec struct{ name, spec string }

func requirementSpecs(lines []string) []nameSpec {
	var out []nameSpec
	for _, line := range lines {
		line, _, _ = strings.Cut(line, " #")
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") || strings.Contains(line, "://") {
			continue
		}
		if name, spec, ok := parseRequirement(line); ok {
			out = append(out, nameSpec{name, spec})
		}
	}
	return out
}

// tomlDoc is a decoded TOML document with its key order (Python's tomllib
// keeps insertion order, which decides how ranges are joined).
type tomlDoc struct {
	data map[string]any
	keys []toml.Key
}

// table returns the table at path; a missing key is an empty table, any
// other type an error (Python would fail on .get()).
func (d tomlDoc) table(path ...string) (map[string]any, error) {
	current := d.data
	for i, key := range path {
		v, ok := current[key]
		if !ok || v == nil {
			return map[string]any{}, nil
		}
		next, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("'%s' is not a table", strings.Join(path[:i+1], "."))
		}
		current = next
	}
	return current, nil
}

// children lists the direct keys of the table at path in document order.
func (d tomlDoc) children(path ...string) []string {
	var out []string
	seen := map[string]bool{}
	for _, key := range d.keys {
		// Implicit parent tables ([a.b.c] defines a.b) appear only as prefixes.
		if len(key) <= len(path) || seen[key[len(path)]] || !slices.Equal([]string(key[:len(path)]), path) {
			continue
		}
		seen[key[len(path)]] = true
		out = append(out, key[len(path)])
	}
	return out
}

func stringItems(v any, onlyStrings bool) ([]string, error) {
	if v == nil {
		return nil, nil
	}
	items, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("expected an array, got %T", v)
	}
	var out []string
	for _, item := range items {
		if s, isString := item.(string); isString {
			out = append(out, s)
		} else if !onlyStrings {
			out = append(out, fmt.Sprint(item))
		}
	}
	return out, nil
}

func pyprojectSpecs(text string) ([]nameSpec, error) {
	var doc tomlDoc
	md, err := toml.Decode(text, &doc.data)
	if err != nil {
		return nil, err
	}
	doc.keys = md.Keys()
	var lines []string
	for _, field := range [][]string{{"project", "dependencies"}, {"build-system", "requires"}} {
		table, err := doc.table(field[0])
		if err != nil {
			return nil, err
		}
		items, err := stringItems(table[field[1]], false)
		if err != nil {
			return nil, err
		}
		lines = append(lines, items...)
	}
	for _, path := range [][]string{{"project", "optional-dependencies"}, {"dependency-groups"}} {
		table, err := doc.table(path...)
		if err != nil {
			return nil, err
		}
		for _, group := range doc.children(path...) {
			// dependency-groups may include {include-group = ...} tables.
			items, err := stringItems(table[group], path[0] == "dependency-groups")
			if err != nil {
				return nil, err
			}
			lines = append(lines, items...)
		}
	}
	specs := requirementSpecs(lines)
	// Poetry: {name = "^1.2"} or {name = {version = "^1.2", ...}}
	tables := [][]string{{"tool", "poetry", "dependencies"}, {"tool", "poetry", "dev-dependencies"}}
	for _, group := range doc.children("tool", "poetry", "group") {
		tables = append(tables, []string{"tool", "poetry", "group", group, "dependencies"})
	}
	for _, path := range tables {
		table, err := doc.table(path...)
		if err != nil {
			return nil, err
		}
		for _, name := range doc.children(path...) {
			value := table[name]
			if inline, ok := value.(map[string]any); ok {
				value = inline["version"]
			}
			if s, ok := value.(string); ok && strings.ToLower(name) != "python" {
				if strings.TrimSpace(s) == "*" {
					s = ""
				}
				specs = append(specs, nameSpec{name, s})
			}
		}
	}
	return specs, nil
}

// jsonStr is Python's str() of a decoded JSON value; numbers keep their
// literal text.
func jsonStr(raw json.RawMessage) string {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return ""
	}
	if _, isNumber := v.(float64); isNumber {
		return strings.TrimSpace(string(raw))
	}
	return pyStr(v)
}

func packageJSONSpecs(text string) ([]nameSpec, error) {
	var data map[string]json.RawMessage
	if err := json.Unmarshal([]byte(text), &data); err != nil {
		return nil, err
	}
	var specs []nameSpec
	for _, key := range []string{"dependencies", "devDependencies", "optionalDependencies"} {
		raw := bytes.TrimSpace(data[key])
		if len(raw) == 0 || string(raw) == "null" {
			continue
		}
		names, values := enrich.OrderedKeys(raw)
		if values == nil {
			return nil, fmt.Errorf("'%s' is not an object", key)
		}
		for _, name := range names {
			value := strings.TrimSpace(jsonStr(values[name]))
			// file:, git+, workspace:, npm: aliases and URLs are not ranges.
			if strings.ContainsAny(value, ":/") {
				continue
			}
			if value == "*" || value == "latest" || value == "x" {
				value = ""
			}
			specs = append(specs, nameSpec{name, value})
		}
	}
	return specs, nil
}

// RegistryKey identifies a package by OSV ecosystem and package key (the
// PEP 503 name for PyPI).
type RegistryKey struct{ Ecosystem, Name string }

// Declared is a manifest constraint and the manifests declaring it.
type Declared struct {
	Constraint string
	Paths      []string
}

var lineContinuation = regexp.MustCompile(`\\\r?\n`)

// DeclaredConstraints maps each declared package to its constraint. PyPI
// ranges declared in several files are intersected (pip must satisfy all of
// them); for npm the shallowest manifest wins, as for a workspace root.
// Unparseable manifests are reported, never guessed at.
func DeclaredConstraints(manifests map[string]string) (map[RegistryKey]Declared, []string) {
	paths := make([]string, 0, len(manifests))
	for path := range manifests {
		paths = append(paths, path)
	}
	SortByDepth(paths)
	type found struct{ constraints, paths []string }
	all := map[RegistryKey]*found{}
	var warnings []string
	for _, path := range paths {
		text, base := manifests[path], path[strings.LastIndex(path, "/")+1:]
		ecosystem := "PyPI"
		var specs []nameSpec
		var err error
		switch base {
		case "package.json":
			ecosystem = "npm"
			specs, err = packageJSONSpecs(text)
		case "pyproject.toml":
			specs, err = pyprojectSpecs(text)
		default:
			// Join backslash line continuations before parsing.
			joined := lineContinuation.ReplaceAllString(text, " ")
			specs = requirementSpecs(strings.Split(strings.ReplaceAll(joined, "\r\n", "\n"), "\n"))
		}
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s could not be parsed: %s", path, err))
			continue
		}
		for _, s := range specs {
			key := RegistryKey{ecosystem, s.name}
			if ecosystem == "PyPI" {
				key.Name = PyPIKey(s.name)
			}
			f := all[key]
			if f == nil {
				f = &found{}
				all[key] = f
			}
			if !slices.Contains(f.paths, path) {
				f.paths = append(f.paths, path)
			}
			if s.spec != "" && !slices.Contains(f.constraints, s.spec) && (ecosystem == "PyPI" || len(f.constraints) == 0) {
				f.constraints = append(f.constraints, s.spec)
			}
		}
	}
	out := make(map[RegistryKey]Declared, len(all))
	for key, f := range all {
		out[key] = Declared{strings.Join(f.constraints, ","), f.paths}
	}
	return out, warnings
}

// SortByDepth orders paths shallowest first, then lexically.
func SortByDepth(paths []string) {
	sort.Slice(paths, func(i, j int) bool {
		if a, b := strings.Count(paths[i], "/"), strings.Count(paths[j], "/"); a != b {
			return a < b
		}
		return paths[i] < paths[j]
	})
}
