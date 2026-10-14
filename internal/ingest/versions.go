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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

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

// pyQuote is urllib.parse.quote: unreserved characters and safe stay as is.
func pyQuote(s, safe string) string {
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
	raw, err := c.getJSON(ctx, c.base("PyPI")+"/pypi/"+pyQuote(name, "")+"/json", nil)
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
	raw, err := c.getJSON(ctx, c.base("npm")+"/"+pyQuote(name, "@/"),
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
	raw, err := c.getJSON(ctx, c.base("crates.io")+"/api/v1/crates/"+pyQuote(name, ""),
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
	raw, err := c.getJSON(ctx, c.base("RubyGems")+"/api/v1/versions/"+pyQuote(name, "")+".json", nil)
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
	raw, err := c.getJSON(ctx, c.base("NuGet")+"/v3-flatcontainer/"+pyQuote(strings.ToLower(name), "")+"/index.json", nil)
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
	raw, err := c.getBytes(ctx, c.base("Go")+"/"+pyQuote(escaped, "/!")+"/@v/list", nil)
	if err != nil {
		return nil, "", err
	}
	return releasesOf(strings.Fields(strings.ToValidUTF8(string(raw), "�")), true), "", nil
}

func (c registryClient) packagist(ctx context.Context, name string) ([]release, string, error) {
	raw, err := c.getJSON(ctx, c.base("Packagist")+"/p2/"+pyQuote(name, "/")+".json", nil)
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
	raw, err := c.getJSON(ctx, c.base("GitHub Actions")+"/repos/"+pyQuote(ownerRepo, "/")+"/git/matching-refs/tags",
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
