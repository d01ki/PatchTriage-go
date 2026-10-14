// Package repository normalizes repository URLs and acquires evidence for
// them: GitHub's Dependency Graph SBOM (no clone, no execution) or, when a
// local deployment explicitly allows it, a static osv-scanner scan of a
// public HTTPS Git clone.
//
// An exported SBOM describes the dependencies GitHub knows about. It is
// useful input, not evidence that every manifest was discovered or that a
// repository is free of vulnerabilities; the provenance says so.
package repository

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/d01ki/PatchTriage-go/internal/ingest"
	"github.com/d01ki/PatchTriage-go/internal/model"
)

const (
	githubHost            = "github.com"
	DefaultMaxSBOMBytes   = 32 * 1024 * 1024
	defaultTimeout        = 45 * time.Second
	maxTreeBytes          = 16 * 1024 * 1024
	maxManifests          = 40
	maxManifestBytes      = 1024 * 1024
	maxErrorBodyBytes     = 64 * 1024
	segmentSafe           = "-._~!$&'()*+,;=:@"
	retrievedAtTimeFormat = "2006-01-02T15:04:05.000000+00:00"
)

// Error is a repository import failure. Status is the HTTP status the GUI
// answers with (Python's exception class decides it there).
type Error struct {
	Status     int
	Message    string
	RetryAfter string
}

func (e *Error) Error() string { return e.Message }

func newError(status int, format string, args ...any) *Error {
	return &Error{Status: status, Message: fmt.Sprintf(format, args...)}
}

// Failure classes, named after the Python exceptions.
func invalidURL(msg string) *Error               { return newError(400, "%s", msg) }
func unsupported(format string, a ...any) *Error { return newError(400, format, a...) }
func fetchError(format string, a ...any) *Error  { return newError(502, format, a...) }
func tooLarge(format string, a ...any) *Error    { return newError(413, format, a...) }

// Reference is a normalized repository reference without credentials or
// query data. Empty Owner/Name/Ref/Selector mean "not applicable".
type Reference struct {
	OriginalURL, NormalizedURL, Provider, Host, Repository string
	Owner, Name, Ref, Selector                             string
}

var (
	ownerPattern      = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$`)
	repositoryPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
	badPercent        = regexp.MustCompile(`%([^0-9A-Fa-f]|.[^0-9A-Fa-f]|.?$)`)
)

func hasControl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return r < 32 || r == 127 })
}

// canonicalHost lowercases an ASCII host and applies the label checks of
// Python's idna codec. Internationalized names are rejected rather than
// guessed at.
func canonicalHost(host string) (string, error) {
	for _, r := range host {
		if r > 127 {
			return "", invalidURL("repository URL contains an invalid host name")
		}
	}
	host = strings.ToLower(host)
	labels := strings.Split(strings.TrimSuffix(host, "."), ".")
	for _, label := range labels {
		if label == "" && host != "" || len(label) > 63 {
			return "", invalidURL("repository URL contains an invalid host name")
		}
	}
	if host == "" || strings.HasSuffix(host, ".") {
		return "", invalidURL("repository URL must contain an unambiguous host name")
	}
	return host, nil
}

func decodedSegments(path string) ([]string, error) {
	if strings.Contains(path, `\`) || badPercent.MatchString(path) {
		return nil, invalidURL("repository URL contains an invalid path encoding")
	}
	var segments []string
	for _, raw := range strings.Split(path, "/") {
		if raw == "" {
			continue
		}
		segment, err := url.PathUnescape(raw)
		if err != nil {
			return nil, invalidURL("repository URL contains an invalid path encoding")
		}
		segment = strings.ToValidUTF8(segment, "�")
		if segment == "." || segment == ".." || strings.ContainsAny(segment, `/\`) || hasControl(segment) {
			return nil, invalidURL("repository URL contains an unsafe path segment")
		}
		segments = append(segments, segment)
	}
	return segments, nil
}

// splitURL is urllib's urlsplit for an absolute URL: netloc and the raw,
// still percent-encoded path.
func splitURL(candidate string) (scheme, netloc, path, query, fragment string) {
	scheme, rest, found := strings.Cut(candidate, ":")
	if !found {
		return "", "", candidate, "", ""
	}
	rest, fragment, _ = strings.Cut(rest, "#")
	rest, query, _ = strings.Cut(rest, "?")
	if strings.HasPrefix(rest, "//") {
		rest = rest[2:]
		end := strings.IndexByte(rest, '/')
		if end < 0 {
			end = len(rest)
		}
		netloc, path = rest[:end], rest[end:]
	} else {
		path = rest
	}
	return scheme, netloc, path, query, fragment
}

// Normalize validates and canonicalizes a GitHub or generic HTTPS Git URL.
// GitHub URLs resolve to their repository root; a tree/<ref> suffix is kept
// as requested provenance. Generic HTTPS URLs are normalized only.
func Normalize(value string) (Reference, error) {
	candidate := strings.TrimSpace(value)
	switch {
	case candidate == "":
		return Reference{}, invalidURL("repository URL is required")
	case hasControl(candidate):
		return Reference{}, invalidURL("repository URL contains control characters")
	case strings.Contains(candidate, `\`):
		return Reference{}, invalidURL("repository URL must use forward slashes")
	}
	scheme, netloc, rawPath, query, fragment := splitURL(candidate)
	if !strings.EqualFold(scheme, "https") {
		return Reference{}, invalidURL("repository URL must use HTTPS")
	}
	// urlsplit takes the host after the last "@".
	hostport := netloc[strings.LastIndex(netloc, "@")+1:]
	hasUser := strings.Contains(netloc, "@")
	host, portText := hostport, ""
	if strings.HasPrefix(hostport, "[") {
		end := strings.IndexByte(hostport, ']')
		if end < 0 {
			return Reference{}, invalidURL("repository URL is malformed")
		}
		host, portText = hostport[1:end], strings.TrimPrefix(hostport[end+1:], ":")
	} else if i := strings.LastIndexByte(hostport, ':'); i >= 0 {
		host, portText = hostport[:i], hostport[i+1:]
	}
	port := -1
	if portText != "" {
		n, err := strconv.Atoi(portText)
		if err != nil || n < 0 || n > 65535 {
			return Reference{}, invalidURL("repository URL is malformed")
		}
		port = n
	}
	switch {
	case netloc == "" || host == "":
		return Reference{}, invalidURL("repository URL must include a host name")
	case hasUser:
		return Reference{}, invalidURL("repository URL must not contain user information")
	case fragment != "":
		return Reference{}, invalidURL("repository URL must not contain a fragment")
	case query != "":
		return Reference{}, invalidURL("repository URL must not contain query parameters")
	}
	host, err := canonicalHost(host)
	if err != nil {
		return Reference{}, err
	}
	segments, err := decodedSegments(rawPath)
	if err != nil {
		return Reference{}, err
	}
	if len(segments) == 0 {
		return Reference{}, invalidURL("repository URL must include a repository path")
	}

	if host == githubHost {
		if port != -1 && port != 443 {
			return Reference{}, invalidURL("github.com repository URLs may not use a custom port")
		}
		if len(segments) < 2 {
			return Reference{}, invalidURL("GitHub URL must include both owner and repository")
		}
		owner, name := segments[0], segments[1]
		if strings.HasSuffix(strings.ToLower(name), ".git") {
			name = name[:len(name)-4]
		}
		if !ownerPattern.MatchString(owner) || strings.Contains(owner, "--") {
			return Reference{}, invalidURL("GitHub URL contains an invalid owner name")
		}
		if !repositoryPattern.MatchString(name) || name == "." || name == ".." || strings.HasSuffix(name, ".git") {
			return Reference{}, invalidURL("GitHub URL contains an invalid repository name")
		}
		ref := Reference{OriginalURL: candidate, NormalizedURL: "https://" + githubHost + "/" + owner + "/" + name,
			Provider: "github", Host: host, Repository: owner + "/" + name, Owner: owner, Name: name}
		if extra := segments[2:]; len(extra) > 0 {
			ref.Selector = strings.ToLower(extra[0])
			if ref.Selector != "tree" || len(extra) < 2 {
				return Reference{}, invalidURL("GitHub URL must point to the repository root or tree/<ref>")
			}
			ref.Ref = strings.Join(extra[1:], "/")
		}
		return ref, nil
	}

	if len(segments) < 2 {
		return Reference{}, invalidURL("generic Git repository URL must include a repository path")
	}
	if port == 0 {
		return Reference{}, invalidURL("repository URL contains an invalid port")
	}
	display := host
	if strings.Contains(host, ":") {
		display = "[" + host + "]"
	}
	if port != -1 && port != 443 {
		display += ":" + strconv.Itoa(port)
	}
	encoded := make([]string, len(segments))
	for i, s := range segments {
		encoded[i] = ingest.PyQuote(s, segmentSafe)
	}
	return Reference{OriginalURL: candidate, NormalizedURL: "https://" + display + strings.TrimRight("/"+strings.Join(encoded, "/"), "/"),
		Provider: "generic_https_git", Host: host, Repository: strings.Join(segments, "/")}, nil
}

// ------------------------------------------------------------ GitHub

// GitHub fetches Dependency Graph SBOMs. Zero fields use the public
// endpoints and Python's limits; tests point the roots at local servers.
type GitHub struct {
	HTTP             *http.Client
	APIRoot, RawRoot string
	MaxBytes         int64
	Timeout          time.Duration
}

func (g GitHub) withDefaults() GitHub {
	if g.HTTP == nil {
		g.HTTP = &http.Client{}
	}
	// Redirects are never followed, so an Authorization header cannot be
	// forwarded to another origin.
	client := *g.HTTP
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	g.HTTP = &client
	if g.APIRoot == "" {
		g.APIRoot = "https://api.github.com"
	}
	if g.RawRoot == "" {
		g.RawRoot = "https://raw.githubusercontent.com"
	}
	if g.MaxBytes == 0 {
		g.MaxBytes = DefaultMaxSBOMBytes
	}
	if g.Timeout == 0 {
		g.Timeout = defaultTimeout
	}
	return g
}

func (g GitHub) get(ctx context.Context, target string, headers map[string]string) (*http.Response, context.CancelFunc, error) {
	ctx, cancel := context.WithTimeout(ctx, g.Timeout)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := g.HTTP.Do(req)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	return resp, cancel, nil
}

func readBounded(resp *http.Response, limit int64) ([]byte, error) {
	exceeded := tooLarge("GitHub SBOM exceeds the %d-byte import limit", limit)
	if resp.ContentLength > limit {
		return nil, exceeded
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fetchError("GitHub SBOM request failed: %s", errorClass(err))
	}
	if int64(len(raw)) > limit {
		return nil, exceeded
	}
	return raw, nil
}

// errorClass names a transport failure without leaking its details.
func errorClass(err error) string {
	var netErr net.Error
	switch {
	case errors.As(err, &netErr) && netErr.Timeout(), errors.Is(err, context.DeadlineExceeded):
		return "TimeoutException"
	case strings.Contains(err.Error(), "dial"):
		return "ConnectError"
	}
	return "RequestError"
}

func errorDetail(raw []byte) string {
	var payload struct {
		Message *string `json:"message"`
	}
	if !utf8.Valid(raw) || json.Unmarshal(raw, &payload) != nil || payload.Message == nil {
		return ""
	}
	return string([]rune(*payload.Message)[:min(300, len([]rune(*payload.Message)))])
}

func githubStatusError(resp *http.Response, raw []byte) *Error {
	status := resp.StatusCode
	suffix := ""
	if detail := errorDetail(raw); detail != "" {
		suffix = ": " + detail
	}
	switch {
	case status == 404:
		return newError(404, "GitHub repository or Dependency Graph SBOM was not found; confirm that the repository is "+
			"visible to the configured credentials and dependency graph data is available%s", suffix)
	case status == 429 || status == 403 && resp.Header.Get("x-ratelimit-remaining") == "0":
		e := newError(429, "GitHub API rate limit reached; retry later or configure GITHUB_TOKEN%s", suffix)
		e.RetryAfter = resp.Header.Get("retry-after")
		if e.RetryAfter == "" {
			e.RetryAfter = resp.Header.Get("x-ratelimit-reset")
		}
		return e
	case status == 401 || status == 403:
		return newError(403, "GitHub denied access to the repository SBOM; confirm repository visibility and "+
			"GITHUB_TOKEN permissions%s", suffix)
	case status >= 300 && status < 400:
		return fetchError("GitHub API returned an unexpected redirect; repository import did not follow it")
	}
	return fetchError("GitHub SBOM API returned HTTP %d%s", status, suffix)
}

// getBounded fetches a manifest or the file tree; any non-200 answer fails.
func (g GitHub) getBounded(ctx context.Context, target string, headers map[string]string, limit int64) ([]byte, error) {
	resp, cancel, err := g.get(ctx, target, headers)
	if err != nil {
		return nil, fetchError("%s", errorClass(err))
	}
	defer cancel()
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fetchError("HTTP %d", resp.StatusCode)
	}
	return readBounded(resp, limit)
}

// SBOM is serialized SPDX content for the regular SBOM ingest path, with
// where it came from and what it can substantiate.
type SBOM struct {
	Content    string
	Provenance map[string]any
}

func parseGitHubSBOM(raw []byte) (map[string]any, []any, error) {
	if !utf8.Valid(raw) {
		return nil, nil, fetchError("GitHub SBOM response is not UTF-8 JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var payload any
	if decoder.Decode(&payload) != nil || decoder.More() {
		return nil, nil, fetchError("GitHub SBOM response is not valid JSON")
	}
	object, _ := payload.(map[string]any)
	sbom, ok := object["sbom"].(map[string]any)
	if !ok {
		return nil, nil, fetchError("GitHub SBOM response is missing the 'sbom' object")
	}
	if !strings.HasPrefix(fmt.Sprint(orEmpty(sbom["spdxVersion"])), "SPDX-") {
		return nil, nil, fetchError("GitHub SBOM response is not a recognized SPDX document")
	}
	packages, ok := sbom["packages"].([]any)
	if !ok {
		return nil, nil, fetchError("GitHub SPDX document is missing its packages list")
	}
	for _, p := range packages {
		if _, ok := p.(map[string]any); !ok {
			return nil, nil, fetchError("GitHub SPDX document contains an invalid package entry")
		}
	}
	return sbom, packages, nil
}

func orEmpty(v any) any {
	if v == nil {
		return ""
	}
	return v
}

// registryKey is the (OSV ecosystem, package key) of a PyPI or npm package.
func registryKey(pkg map[string]any) (ingest.RegistryKey, bool) {
	raw, _ := json.Marshal(pkg)
	typ, namespace, name, _ := model.ParsePurl(ingest.SPDXPackagePurl(raw))
	switch {
	case typ == "pypi" && name != "":
		return ingest.RegistryKey{Ecosystem: "PyPI", Name: ingest.PyPIKey(name)}, true
	case typ == "npm" && name != "" && namespace != "":
		return ingest.RegistryKey{Ecosystem: "npm", Name: namespace + "/" + name}, true
	case typ == "npm" && name != "":
		return ingest.RegistryKey{Ecosystem: "npm", Name: name}, true
	}
	return ingest.RegistryKey{}, false
}

// restoreDeclaredRanges puts back, as versionInfo, the version ranges
// GitHub's SBOM drops. Without the range only the newest release is left to
// check, which is usually the patched one. Manifests are read as text
// through the tree API and raw file host; nothing is executed.
func (g GitHub) restoreDeclaredRanges(ctx context.Context, packages []any, ref Reference, headers map[string]string) []string {
	var missing []map[string]any
	for _, p := range packages {
		pkg := p.(map[string]any)
		if _, ok := registryKey(pkg); ok && strings.TrimSpace(fmt.Sprint(orEmpty(pkg["versionInfo"]))) == "" {
			missing = append(missing, pkg)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	treeRef := "HEAD"
	if ref.Ref != "" {
		treeRef = ref.Ref
	}
	treeRef = ingest.PyQuote(treeRef, "")
	repo := ingest.PyQuote(ref.Owner, "") + "/" + ingest.PyQuote(ref.Name, "")
	raw, err := g.getBounded(ctx, g.APIRoot+"/repos/"+repo+"/git/trees/"+treeRef+"?recursive=1", headers, maxTreeBytes)
	var tree struct {
		Tree      []json.RawMessage `json:"tree"`
		Truncated any               `json:"truncated"`
	}
	if err == nil {
		if json.Unmarshal(raw, &tree) != nil || tree.Tree == nil {
			err = errors.New("unexpected tree response")
		}
	}
	if err != nil {
		return []string{fmt.Sprintf("%d PyPI/npm dependencies are listed without their declared version range, and "+
			"the repository file list needed to restore it was unavailable (%s).", len(missing), err)}
	}
	var paths []string
	for _, entry := range tree.Tree {
		var e struct {
			Path *string `json:"path"`
			Type string  `json:"type"`
		}
		if json.Unmarshal(entry, &e) == nil && e.Type == "blob" && e.Path != nil && ingest.IsManifest(*e.Path) {
			paths = append(paths, *e.Path)
		}
	}
	ingest.SortByDepth(paths)
	var warnings []string
	if truncated, _ := tree.Truncated.(bool); truncated {
		warnings = append(warnings, "GitHub truncated the repository file list; some manifests may not have been read.")
	}
	if len(paths) > maxManifests {
		warnings = append(warnings, fmt.Sprintf("Only the first %d of %d manifests were read.", maxManifests, len(paths)))
		paths = paths[:maxManifests]
	}
	rawHeaders := map[string]string{}
	for _, k := range []string{"Authorization", "User-Agent"} {
		if v, ok := headers[k]; ok {
			rawHeaders[k] = v
		}
	}
	manifests := map[string]string{}
	for _, path := range paths {
		body, err := g.getBounded(ctx, g.RawRoot+"/"+repo+"/"+treeRef+"/"+ingest.PyQuote(path, "/"), rawHeaders, maxManifestBytes)
		if err == nil && !utf8.Valid(body) {
			err = errors.New("'utf-8' codec can't decode the file")
		}
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s could not be read (%s).", path, err))
			continue
		}
		manifests[path] = string(body)
	}
	constraints, parseWarnings := ingest.DeclaredConstraints(manifests)
	warnings = append(warnings, parseWarnings...)
	restored := 0
	for _, pkg := range missing {
		key, _ := registryKey(pkg)
		if declared := constraints[key]; declared.Constraint != "" {
			pkg["versionInfo"] = declared.Constraint
			pkg["sourceInfo"] = fmt.Sprintf("Declared range from %s; restored by PatchTriage because GitHub's SBOM "+
				"omits version ranges.", strings.Join(declared.Paths, ", "))
			restored++
		}
	}
	if restored > 0 {
		warnings = append([]string{fmt.Sprintf("GitHub's SBOM omits declared version ranges; %d of %d were restored "+
			"from %d manifest(s).", restored, len(missing), len(manifests))}, warnings...)
	}
	if restored < len(missing) {
		warnings = append(warnings, fmt.Sprintf("%d dependencies have no declared range in a readable manifest and "+
			"are checked at their newest release.", len(missing)-restored))
	}
	return warnings
}

// FetchSBOM fetches a GitHub repository's provider-generated SPDX SBOM.
// Public repositories need no token; an operator may supply one for a
// repository it authorizes.
func (g GitHub) FetchSBOM(ctx context.Context, ref Reference, token string) (SBOM, error) {
	if ref.Provider != "github" || ref.Owner == "" || ref.Name == "" {
		return SBOM{}, unsupported("repository provider '%s' is not supported; this importer currently supports "+
			"github.com repositories", ref.Provider)
	}
	g = g.withDefaults()
	apiURL := "https://api.github.com/repos/" + ingest.PyQuote(ref.Owner, "") + "/" + ingest.PyQuote(ref.Name, "") +
		"/dependency-graph/sbom"
	headers := map[string]string{"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
		"User-Agent": "patchtriage/0.6"}
	if token != "" {
		headers["Authorization"] = "Bearer " + token
	}
	resp, cancel, err := g.get(ctx, g.APIRoot+strings.TrimPrefix(apiURL, "https://api.github.com"), headers)
	if err != nil {
		if errorClass(err) == "TimeoutException" {
			return SBOM{}, fetchError("GitHub SBOM request timed out")
		}
		return SBOM{}, fetchError("GitHub SBOM request failed: %s", errorClass(err))
	}
	if resp.StatusCode != 200 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		resp.Body.Close()
		cancel()
		return SBOM{}, githubStatusError(resp, raw)
	}
	raw, err := readBounded(resp, g.MaxBytes)
	resp.Body.Close()
	cancel()
	if err != nil {
		return SBOM{}, err
	}
	sbom, packages, err := parseGitHubSBOM(raw)
	if err != nil {
		return SBOM{}, err
	}
	warnings := []string{"Coverage is limited to dependencies represented in GitHub's Dependency Graph; it is not " +
		"proof that every manifest was discovered or that the repository has no vulnerable components."}
	warnings = append(warnings, g.restoreDeclaredRanges(ctx, packages, ref, headers)...)

	status := "provider_reported"
	if ref.Ref != "" {
		status = "partial"
		warnings = append(warnings, fmt.Sprintf("The GitHub Dependency Graph SBOM endpoint does not accept a ref; the "+
			"requested tree ref '%s' was not independently resolved and the exported graph may represent the "+
			"default branch.", ref.Ref))
	}
	if len(packages) == 0 {
		status = "incomplete"
		warnings = append(warnings, "GitHub returned an SPDX document with zero packages; treat this as incomplete "+
			"coverage, not a clean vulnerability result.")
	}
	refLabel := ref.Ref
	if refLabel == "" {
		refLabel = "default_branch"
	}
	var content bytes.Buffer
	encoder := json.NewEncoder(&content)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(sbom); err != nil {
		return SBOM{}, err
	}
	return SBOM{Content: strings.TrimSuffix(content.String(), "\n"), Provenance: map[string]any{
		"provider": "github_dependency_graph", "repository": ref.Repository, "ref": refLabel,
		"resolved_url": ref.NormalizedURL, "api_url": apiURL, "format": "spdx", "component_count": len(packages),
		"coverage_status": status, "warnings": warnings,
		"retrieved_at": time.Now().UTC().Format(retrievedAtTimeFormat),
	}}, nil
}

// ------------------------------------------------------------ acquisition

// Evidence acquired from a repository URL, ready for ingestion.
type Evidence struct {
	Content, Format string
	Provenance      map[string]any
}

// GenericEnabled reports whether generic HTTPS Git scanning is enabled; it is
// opt-in and never offered in public mode.
func GenericEnabled() bool {
	mode := strings.ToLower(envOr("PATCHTRIAGE_DEPLOYMENT_MODE", "local"))
	switch strings.ToLower(envOr("PATCHTRIAGE_ALLOW_GENERIC_REPOSITORIES", "false")) {
	case "1", "true", "yes", "on":
		return mode != "public"
	}
	return false
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// Acquirer acquires repository evidence the same way for the GUI and CLI.
type Acquirer struct {
	GitHub GitHub
	Local  LocalScanner
}

// Acquire imports github.com through the Dependency Graph SBOM; other HTTPS
// Git hosts are statically scanned only when allowGeneric.
func (a Acquirer) Acquire(ctx context.Context, repositoryURL, token string, maxBytes int64, allowGeneric bool) (Evidence, error) {
	ref, err := Normalize(repositoryURL)
	if err != nil {
		return Evidence{}, err
	}
	if ref.Provider == "github" {
		g := a.GitHub
		g.MaxBytes = maxBytes
		sbom, err := g.FetchSBOM(ctx, ref, token)
		if err != nil {
			return Evidence{}, err
		}
		return Evidence{sbom.Content, "spdx", sbom.Provenance}, nil
	}
	if !allowGeneric {
		return Evidence{}, newError(400, "this deployment imports public GitHub repositories; generic HTTPS Git "+
			"scanning is available only in an explicitly enabled local/Docker deployment")
	}
	local := a.Local
	local.MaxOutputBytes = maxBytes
	return local.Scan(ctx, ref)
}
