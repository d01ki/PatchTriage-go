package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNormalizeGitHubURLs(t *testing.T) {
	for url, want := range map[string][2]string{
		"https://github.com/acme/widget":              {"https://github.com/acme/widget", "acme/widget"},
		" HTTPS://GitHub.com/Acme-Co/widget.py.git/ ": {"https://github.com/Acme-Co/widget.py", "Acme-Co/widget.py"},
		"https://github.com/acme/.github":             {"https://github.com/acme/.github", "acme/.github"},
		"https://github.com:443/acme/widget":          {"https://github.com/acme/widget", "acme/widget"},
	} {
		ref, err := Normalize(url)
		if err != nil || ref.Provider != "github" || ref.NormalizedURL != want[0] || ref.Repository != want[1] || ref.Ref != "" {
			t.Errorf("Normalize(%q) = %+v, %v", url, ref, err)
		}
	}
	ref, err := Normalize("https://github.com/acme/widget/tree/release/2026.1")
	if err != nil || ref.NormalizedURL != "https://github.com/acme/widget" || ref.Selector != "tree" || ref.Ref != "release/2026.1" {
		t.Errorf("tree ref = %+v, %v", ref, err)
	}
}

func TestNormalizeGenericURLWithoutTreatingSpoofAsGitHub(t *testing.T) {
	ref, err := Normalize("https://GitLab.Example:8443/group/subgroup/project.git/")
	if err != nil || ref.Provider != "generic_https_git" || ref.Host != "gitlab.example" ||
		ref.Repository != "group/subgroup/project.git" || ref.NormalizedURL != "https://gitlab.example:8443/group/subgroup/project.git" {
		t.Errorf("generic = %+v, %v", ref, err)
	}
	spoof, err := Normalize("https://github.com.evil.test/acme/widget")
	if err != nil || spoof.Provider != "generic_https_git" || spoof.Host != "github.com.evil.test" {
		t.Errorf("spoof = %+v, %v", spoof, err)
	}
	encoded, err := Normalize("https://git.example/group/my%20repo")
	if err != nil || encoded.NormalizedURL != "https://git.example/group/my%20repo" || encoded.Repository != "group/my repo" {
		t.Errorf("encoded = %+v, %v", encoded, err)
	}
}

func TestRejectsAmbiguousOrUnsafeURLs(t *testing.T) {
	for _, url := range []string{
		"", "git@github.com:acme/widget.git", "http://github.com/acme/widget", "ssh://github.com/acme/widget",
		"file:///tmp/widget", "https://user@github.com/acme/widget", "https://user:secret@github.com/acme/widget",
		"https://github.com/acme/widget#readme", "https://github.com/acme/widget?tab=readme", "https://github.com",
		"https://github.com/acme", "https://github.com:444/acme/widget", "https://github.com/acme/widget/issues/1",
		"https://github.com/acme/widget/tree", "https://github.com/acme/widget/tree/%2e%2e",
		"https://github.com/acme%2Fwidget/other", `https://github.com/acme\widget/repo`, "https://github.com/acme/widget%ZZ",
		"https://github.com/acme--spoof/widget", "https://github.com/acme/widget.git.git", "https://gitlab.example/project",
		"https://github.com./acme/widget", "https://git.example:0/a/b", "https://git.example:99999/a/b",
	} {
		ref, err := Normalize(url)
		if e, ok := err.(*Error); !ok || e.Status != 400 {
			t.Errorf("Normalize(%q) = %+v, %v; want a validation error", url, ref, err)
		}
	}
}

func githubPayload(packages []map[string]any) map[string]any {
	if packages == nil {
		packages = []map[string]any{
			{"SPDXID": "SPDXRef-Package-npm-lodash", "name": "lodash", "versionInfo": "4.17.20", "externalRefs": []any{}},
			{"SPDXID": "SPDXRef-Package-pypi-requests", "name": "requests", "versionInfo": "2.31.0", "externalRefs": []any{}},
		}
	}
	return map[string]any{"sbom": map[string]any{"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT",
		"name": "acme-widget", "packages": packages}}
}

// fakeGitHub serves handler on both the API and raw roots.
func fakeGitHub(t *testing.T, handler http.HandlerFunc) GitHub {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return GitHub{HTTP: server.Client(), APIRoot: server.URL, RawRoot: server.URL + "/raw"}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func fetch(t *testing.T, g GitHub, url, token string) (SBOM, error) {
	t.Helper()
	ref, err := Normalize(url)
	if err != nil {
		t.Fatal(err)
	}
	return g.FetchSBOM(context.Background(), ref, token)
}

func TestFetchPublicGitHubSBOMReturnsSPDXAndProvenance(t *testing.T) {
	var seen *http.Request
	g := fakeGitHub(t, func(w http.ResponseWriter, r *http.Request) {
		seen = r
		writeJSON(w, 200, githubPayload(nil))
	})
	result, err := fetch(t, g, "https://github.com/acme/widget.git", "")
	if err != nil {
		t.Fatal(err)
	}
	if seen.URL.Path != "/repos/acme/widget/dependency-graph/sbom" || seen.Header.Get("Accept") != "application/vnd.github+json" ||
		seen.Header.Get("X-GitHub-Api-Version") != "2022-11-28" || seen.Header.Get("Authorization") != "" {
		t.Errorf("request = %s %v", seen.URL, seen.Header)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(result.Content), &doc); err != nil || doc["sbom"] != nil || doc["spdxVersion"] != "SPDX-2.3" {
		t.Errorf("content = %s", result.Content)
	}
	p := result.Provenance
	if p["provider"] != "github_dependency_graph" || p["repository"] != "acme/widget" || p["ref"] != "default_branch" ||
		p["resolved_url"] != "https://github.com/acme/widget" || p["api_url"] != "https://api.github.com/repos/acme/widget/dependency-graph/sbom" ||
		p["format"] != "spdx" || p["component_count"] != 2 || p["coverage_status"] != "provider_reported" ||
		!strings.Contains(p["warnings"].([]string)[0], "not proof") {
		t.Errorf("provenance = %v", p)
	}
}

func TestTokenIsSentAsHeaderOnly(t *testing.T) {
	g := fakeGitHub(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-secret" || strings.Contains(r.URL.String(), "test-secret") {
			t.Errorf("request %s %v", r.URL, r.Header)
		}
		writeJSON(w, 200, githubPayload(nil))
	})
	if _, err := fetch(t, g, "https://github.com/acme/widget", "test-secret"); err != nil {
		t.Fatal(err)
	}
}

func TestTreeRefIsPartialAndEmptyDocumentIncomplete(t *testing.T) {
	var packages []map[string]any
	g := fakeGitHub(t, func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, githubPayload(packages)) })
	result, err := fetch(t, g, "https://github.com/acme/widget/tree/release/2026.1", "")
	if err != nil || result.Provenance["ref"] != "release/2026.1" || result.Provenance["coverage_status"] != "partial" ||
		!strings.Contains(strings.Join(result.Provenance["warnings"].([]string), " "), "does not accept a ref") {
		t.Errorf("tree ref = %v, %v", result.Provenance, err)
	}
	packages = []map[string]any{}
	result, err = fetch(t, g, "https://github.com/acme/widget", "")
	if err != nil || result.Provenance["component_count"] != 0 || result.Provenance["coverage_status"] != "incomplete" ||
		!strings.Contains(strings.Join(result.Provenance["warnings"].([]string), " "), "zero packages") {
		t.Errorf("empty = %v, %v", result.Provenance, err)
	}
}

func TestGitHubHTTPFailuresHaveSpecificStatuses(t *testing.T) {
	cases := []struct {
		status  int
		headers map[string]string
		want    int
	}{
		{404, nil, 404}, {401, nil, 403}, {403, nil, 403}, {429, map[string]string{"retry-after": "60"}, 429},
		{500, nil, 502}, {302, map[string]string{"location": "https://evil.test/"}, 502},
		{403, map[string]string{"x-ratelimit-remaining": "0", "x-ratelimit-reset": "42"}, 429},
	}
	for _, c := range cases {
		g := fakeGitHub(t, func(w http.ResponseWriter, r *http.Request) {
			for k, v := range c.headers {
				w.Header().Set(k, v)
			}
			writeJSON(w, c.status, map[string]string{"message": "provider detail"})
		})
		_, err := fetch(t, g, "https://github.com/acme/widget", "")
		e, ok := err.(*Error)
		if !ok || e.Status != c.want || !strings.Contains(e.Message, "GitHub") {
			t.Errorf("HTTP %d: err = %v", c.status, err)
		}
		if c.headers["x-ratelimit-reset"] == "42" && e.RetryAfter != "42" {
			t.Errorf("retry hint = %q", e.RetryAfter)
		}
	}
}

func TestLargeErrorBodyKeepsClassification(t *testing.T) {
	g := fakeGitHub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		_, _ = w.Write([]byte(strings.Repeat("x", 100_000)))
	})
	g.MaxBytes = 10
	if _, err := fetch(t, g, "https://github.com/acme/widget", ""); err.(*Error).Status != 404 {
		t.Errorf("err = %v", err)
	}
}

func TestRejectsInvalidProviderContent(t *testing.T) {
	for _, body := range []string{`[]`, `{}`, `{"sbom": []}`, `{"sbom": {}}`,
		`{"sbom": {"spdxVersion": "CycloneDX-1.5", "packages": []}}`, `{"sbom": {"spdxVersion": "SPDX-2.3"}}`,
		`{"sbom": {"spdxVersion": "SPDX-2.3", "packages": ["bad"]}}`, "not json", "\xff\xfe"} {
		g := fakeGitHub(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) })
		if _, err := fetch(t, g, "https://github.com/acme/widget", ""); err == nil || err.(*Error).Status != 502 {
			t.Errorf("%q: err = %v", body, err)
		}
	}
}

func TestResponseSizeIsLimited(t *testing.T) {
	content, _ := json.Marshal(githubPayload(nil))
	g := fakeGitHub(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Transfer-Encoding", "chunked") // no trusted Content-Length
		_, _ = w.Write(content)
	})
	g.MaxBytes = int64(len(content) - 1)
	_, err := fetch(t, g, "https://github.com/acme/widget", "")
	if e, ok := err.(*Error); !ok || e.Status != 413 || !strings.Contains(e.Message, "import limit") {
		t.Errorf("err = %v", err)
	}
	g = fakeGitHub(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "9999")
		_, _ = w.Write([]byte("{}"))
	})
	g.MaxBytes = 100
	if _, err := fetch(t, g, "https://github.com/acme/widget", ""); err == nil || err.(*Error).Status != 413 {
		t.Errorf("content-length err = %v", err)
	}
}

func TestGenericProviderIsUnsupportedWithoutNetworkRequest(t *testing.T) {
	requested := false
	g := fakeGitHub(t, func(w http.ResponseWriter, r *http.Request) { requested = true })
	_, err := fetch(t, g, "https://gitlab.example/group/project.git", "")
	if err == nil || !strings.Contains(err.Error(), "github.com") || requested {
		t.Errorf("err = %v, requested = %v", err, requested)
	}
	_, err = Acquirer{GitHub: g}.Acquire(context.Background(), "https://gitlab.example/group/project.git", "", 1<<20, false)
	if err == nil || err.(*Error).Status != 400 || requested {
		t.Errorf("acquire err = %v", err)
	}
}

func versionless(name, purl string) map[string]any {
	return map[string]any{"SPDXID": "SPDXRef-" + name, "name": name, "externalRefs": []any{map[string]any{
		"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": purl}}}
}

func TestDeclaredRangesDroppedByGitHubAreRestored(t *testing.T) {
	files := map[string]string{
		"requirements.txt": "fastapi>=0.104.0\npython_multipart>=0.0.6\n",
		"web/package.json": `{"dependencies": {"@acme/ui": "^1.2.0"}}`,
		"README.md":        "fastapi==0.1",
	}
	var requested []string
	g := fakeGitHub(t, func(w http.ResponseWriter, r *http.Request) {
		requested = append(requested, r.URL.Path)
		switch {
		case strings.HasSuffix(r.URL.Path, "/dependency-graph/sbom"):
			writeJSON(w, 200, githubPayload([]map[string]any{versionless("fastapi", "pkg:pypi/fastapi"),
				versionless("python-multipart", "pkg:pypi/python-multipart"), versionless("@acme/ui", "pkg:npm/%40acme/ui"),
				versionless("left-pad", "pkg:npm/left-pad")}))
		case strings.Contains(r.URL.Path, "/git/trees/HEAD"):
			var tree []map[string]string
			for path := range files {
				tree = append(tree, map[string]string{"path": path, "type": "blob"})
			}
			writeJSON(w, 200, map[string]any{"tree": tree})
		case strings.HasPrefix(r.URL.Path, "/raw/acme/widget/HEAD/"):
			_, _ = w.Write([]byte(files[strings.TrimPrefix(r.URL.Path, "/raw/acme/widget/HEAD/")]))
		default:
			http.NotFound(w, r)
		}
	})
	result, err := fetch(t, g, "https://github.com/acme/widget", "")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct{ Packages []map[string]any }
	_ = json.Unmarshal([]byte(result.Content), &doc)
	packages := map[string]map[string]any{}
	for _, p := range doc.Packages {
		packages[p["name"].(string)] = p
	}
	if packages["fastapi"]["versionInfo"] != ">=0.104.0" || packages["python-multipart"]["versionInfo"] != ">=0.0.6" ||
		packages["@acme/ui"]["versionInfo"] != "^1.2.0" || packages["left-pad"]["versionInfo"] != nil ||
		!strings.Contains(packages["fastapi"]["sourceInfo"].(string), "requirements.txt") {
		t.Errorf("packages = %v", packages)
	}
	if strings.Contains(strings.Join(requested, " "), "README.md") {
		t.Errorf("non-manifest fetched: %v", requested)
	}
	warnings := strings.Join(result.Provenance["warnings"].([]string), "\n")
	if !strings.Contains(warnings, "3 of 4 were restored") || !strings.Contains(warnings, "1 dependencies have no declared range") {
		t.Errorf("warnings = %s", warnings)
	}
}

func TestUnavailableFileListLeavesSBOMUsable(t *testing.T) {
	g := fakeGitHub(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/dependency-graph/sbom") {
			writeJSON(w, 200, githubPayload([]map[string]any{versionless("fastapi", "pkg:pypi/fastapi")}))
			return
		}
		writeJSON(w, 403, map[string]string{"message": "rate limited"})
	})
	result, err := fetch(t, g, "https://github.com/acme/widget", "")
	if err != nil {
		t.Fatal(err)
	}
	warnings := strings.Join(result.Provenance["warnings"].([]string), "\n")
	if strings.Contains(result.Content, "versionInfo") || !strings.Contains(warnings, "file list") || !strings.Contains(warnings, "HTTP 403") {
		t.Errorf("content %s warnings %s", result.Content, warnings)
	}
}

func TestNormalizeOwnerURL(t *testing.T) {
	ref, err := NormalizeOwner("https://github.com/Example-Org")
	if err != nil || ref.Owner != "Example-Org" || ref.NormalizedURL != "https://github.com/Example-Org" {
		t.Errorf("owner = %+v, %v", ref, err)
	}
	for _, url := range []string{"https://github.com/owner/repository", "https://github.com/", "https://gitlab.com/owner",
		"http://github.com/owner", "https://github.com/owner?tab=repos", "https://user:pass@github.com/owner",
		"https://github.com/-bad-", "", "https://github.com:444/owner", "https://github.com/owner#x"} {
		if _, err := NormalizeOwner(url); err == nil || err.(*Error).Status != 400 {
			t.Errorf("NormalizeOwner(%q) err = %v", url, err)
		}
	}
}

func ownerRepo(name string, fork, archived bool) map[string]any {
	return map[string]any{"full_name": "acme/" + name, "html_url": "https://github.com/acme/" + name,
		"default_branch": "main", "pushed_at": "2026-07-01T00:00:00Z", "fork": fork, "archived": archived}
}

func listOwner(t *testing.T, repos []map[string]any, limit int) (OwnerListing, *[]string) {
	t.Helper()
	var queries []string
	g := fakeGitHub(t, func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.RawQuery)
		if r.URL.Query().Get("page") != "1" {
			writeJSON(w, 200, []any{})
			return
		}
		writeJSON(w, 200, repos)
	})
	ref, _ := NormalizeOwner("https://github.com/acme")
	listing, err := g.ListOwner(context.Background(), ref, "", limit, false, false)
	if err != nil {
		t.Fatal(err)
	}
	return listing, &queries
}

func TestListingFiltersForksArchivedAndCapsSelection(t *testing.T) {
	listing, queries := listOwner(t, []map[string]any{ownerRepo("app", false, false), ownerRepo("fork-of-lib", true, false),
		ownerRepo("museum", false, true), ownerRepo("api", false, false), {"full_name": "bad"}}, 10)
	var names []string
	for _, r := range listing.Repositories {
		names = append(names, r.FullName)
	}
	if strings.Join(names, ",") != "acme/app,acme/api" || listing.SkippedForks != 1 || listing.SkippedArchived != 1 ||
		listing.TotalListed != 4 || listing.Truncated || len(*queries) != 1 ||
		(*queries)[0] != "per_page=100&page=1&sort=pushed&direction=desc" {
		t.Errorf("listing = %+v queries %v", listing, *queries)
	}
	var five []map[string]any
	for i := range 5 {
		five = append(five, ownerRepo(fmt.Sprintf("repo%d", i), false, false))
	}
	listing, _ = listOwner(t, five, 2)
	if len(listing.Repositories) != 2 || !listing.Truncated || !strings.Contains(strings.Join(listing.Warnings, " "), "capped") {
		t.Errorf("capped listing = %+v", listing)
	}
}

func TestListingMapsRateLimitAndNotFound(t *testing.T) {
	for _, c := range []struct {
		status  int
		headers map[string]string
		want    int
	}{{404, nil, 404}, {403, map[string]string{"x-ratelimit-remaining": "0", "x-ratelimit-reset": "9"}, 429}, {403, nil, 403}} {
		g := fakeGitHub(t, func(w http.ResponseWriter, r *http.Request) {
			for k, v := range c.headers {
				w.Header().Set(k, v)
			}
			writeJSON(w, c.status, []any{})
		})
		ref, _ := NormalizeOwner("https://github.com/acme")
		if _, err := g.ListOwner(context.Background(), ref, "", 5, false, false); err == nil || err.(*Error).Status != c.want {
			t.Errorf("HTTP %d: err = %v", c.status, err)
		}
	}
}
