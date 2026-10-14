package ingest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/d01ki/PatchTriage-go/internal/model"
)

// osvResponses mirrors testdata/osv_responses.json.
type osvResponses struct {
	Queries map[string][]string        `json:"queries"`
	Vulns   map[string]json.RawMessage `json:"vulns"`
}

func loadOSVResponses(t *testing.T) osvResponses {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/osv_responses.json")
	if err != nil {
		t.Fatal(err)
	}
	var r osvResponses
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

// fakeOSV serves querybatch and vulnerability details like the Python
// golden generator's mock transport. batch overrides the querybatch reply.
func fakeOSV(t *testing.T, r osvResponses, batch http.HandlerFunc) (*OSVClient, *int32) {
	t.Helper()
	var details int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/v1/querybatch" {
			if batch != nil {
				batch(w, req)
				return
			}
			var body struct {
				Queries []struct {
					Package map[string]string `json:"package"`
					Version string            `json:"version"`
				} `json:"queries"`
			}
			_ = json.NewDecoder(req.Body).Decode(&body)
			var results []map[string]any
			for _, q := range body.Queries {
				key := q.Package["purl"]
				if key == "" {
					key = q.Package["ecosystem"] + ":" + q.Package["name"] + "@" + q.Version
				}
				var vulns []map[string]string
				for _, id := range r.Queries[key] {
					vulns = append(vulns, map[string]string{"id": id})
				}
				results = append(results, map[string]any{"vulns": vulns})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
			return
		}
		atomic.AddInt32(&details, 1)
		id := strings.TrimPrefix(req.URL.Path, "/v1/vulns/")
		if record, ok := r.Vulns[id]; ok {
			_, _ = w.Write(record)
			return
		}
		http.Error(w, `{"code":5}`, http.StatusNotFound)
	}))
	t.Cleanup(server.Close)
	registries, _ := fakeRegistry(t, nil) // no test reaches a real registry
	return &OSVClient{HTTP: server.Client(), BaseURL: server.URL, CacheDir: t.TempDir(),
		RegistryURLs: registries.urls}, &details
}

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("../../testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestIsSBOM(t *testing.T) {
	if IsSBOM(readTestdata(t, "sbom_cyclonedx.json")) != "cyclonedx" ||
		IsSBOM(readTestdata(t, "sbom_spdx.json")) != "spdx" ||
		IsSBOM(fixture(t, "trivy_sample.json")) != "" {
		t.Error("SBOM detection differs from Python is_sbom")
	}
}

func TestIsConcrete(t *testing.T) {
	cases := map[string]bool{
		"1.2.3": true, "v45.0.9": true, "4.*.*": false, ">= 2.5": false, "^1.2": false,
		"main": false, "release/v1": false, "6.x": false, "": false, "  ": false, "2024-01-01": true,
	}
	for in, want := range cases {
		if got := isConcrete(in); got != want {
			t.Errorf("isConcrete(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestParseSBOMComponents(t *testing.T) {
	cyclone, err := ParseSBOMComponents(readTestdata(t, "sbom_cyclonedx.json"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range cyclone {
		names = append(names, c.Name)
	}
	sort.Strings(names)
	if strings.Join(names, ",") != "django,lodash,sqlparse" {
		t.Errorf("CycloneDX components (nested included) = %v", names)
	}
	spdx, err := ParseSBOMComponents(readTestdata(t, "sbom_spdx.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range spdx {
		if c.Name == "lodash" && (c.Purl != "pkg:npm/lodash@4.17.20" || c.Ecosystem != "npm" || c.Version != "4.17.20") {
			t.Errorf("SPDX lodash = %+v", c)
		}
	}
	if len(spdx) != 2 {
		t.Errorf("SPDX components = %d, want 2 (document subject excluded)", len(spdx))
	}
}

func TestLoadSBOMAgainstRecordedOSV(t *testing.T) {
	client, _ := fakeOSV(t, loadOSVResponses(t), nil)
	path := filepath.Join("../../testdata", "sbom_cyclonedx.json")
	result, err := LoadFile(context.Background(), path, "", nil, client)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, f := range result.Findings {
		ids = append(ids, f.VulnID+"/"+f.Package.FixedVersion+"/"+string(f.Severity))
		if f.SourceScanner != "osv-sbom" || f.Asset.Identifier != "sbom_cyclonedx.json" || f.Asset.Kind != "sbom" {
			t.Errorf("unexpected finding %+v", f)
		}
	}
	sort.Strings(ids)
	want := "CVE-2021-23337/4.17.21/high,CVE-2021-32839/0.4.2/medium,CVE-2021-33203/3.2.4/unknown,CVE-2022-34265/3.2.14/critical"
	if strings.Join(ids, ",") != want {
		t.Errorf("findings = %v", ids)
	}
	cov := result.Coverage
	if cov["complete"] != false || cov["queried_components"] != 3 || cov["vulnerability_ids"] != 5 ||
		cov["vulnerability_details_resolved"] != 4 || cov["vulnerability_details_failed"] != 1 {
		t.Errorf("coverage = %v", cov)
	}
	errs := cov["errors"].([]string)
	if len(errs) != 1 || !strings.HasPrefix(errs[0], "OSV-2099-MISSING: Client error '404 Not Found' for url '") {
		t.Errorf("errors = %q", errs)
	}
}

func pypiReleases(versions ...string) string {
	releases := map[string]any{}
	for _, v := range versions {
		releases[v] = []map[string]bool{{"yanked": false}}
	}
	raw, _ := json.Marshal(map[string]any{"releases": releases})
	return string(raw)
}

// recordingOSV answers every query with no vulnerabilities and records it.
func recordingOSV(t *testing.T, routes map[string]string) (*OSVClient, *[]string) {
	t.Helper()
	var queries []string
	client, _ := fakeOSV(t, osvResponses{}, func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Queries []json.RawMessage }
		_ = json.NewDecoder(r.Body).Decode(&body)
		results := []map[string]any{}
		for _, q := range body.Queries {
			queries = append(queries, string(q))
			results = append(results, map[string]any{})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
	})
	registries, _ := fakeRegistry(t, routes)
	client.RegistryURLs = registries.urls
	return client, &queries
}

func TestLoadSBOMResolvesVersionlessAndWildcardComponents(t *testing.T) {
	// GitHub drops ">=2.5" entirely and records actions/checkout@v6 as 6.*.*.
	client, queries := recordingOSV(t, map[string]string{
		"/pypi/pydantic/": pypiReleases("2.10.0", "2.11.7", "3.0.0b1"),
		"/@scope/ui":      `{"dist-tags": {"latest": "3.1.0"}, "versions": {"3.1.0": {}, "3.2.0-rc.1": {}, "2.9.9": {}}}`,
		"/repos/actions/checkout/git/matching-refs/tags": `[{"ref": "refs/tags/v5.0.0"}, {"ref": "refs/tags/v6.0.1"},
			{"ref": "refs/tags/v6"}, {"ref": "refs/tags/v7.0.0-beta"}]`,
	})
	doc := `{"bomFormat": "CycloneDX", "components": [
		{"name": "pydantic", "purl": "pkg:pypi/pydantic"},
		{"name": "@scope/ui", "purl": "pkg:npm/%40scope/ui"},
		{"name": "actions/checkout", "version": "6.*.*", "purl": "pkg:githubactions/actions/checkout@6.%2A.%2A"}]}`
	result, err := LoadFile(context.Background(), writeTemp(t, "bom.json", doc), "", nil, client)
	if err != nil {
		t.Fatal(err)
	}
	cov := result.Coverage
	inferred := cov["inferred_versions"].([]map[string]string)
	var got []string
	for _, item := range inferred {
		got = append(got, item["version"]+"|"+item["basis"])
	}
	if strings.Join(got, ",") != "2.11.7|newest release,3.1.0|newest release,6.0.1|newest release matching 6.*.*" ||
		inferred[2]["constraint"] != "6.*.*" || !strings.HasPrefix(inferred[0]["source"], "newest release (PyPI, ") {
		t.Errorf("inferred = %v", inferred)
	}
	if cov["queried_components"] != 3 || cov["unqueryable_components"] != 0 || cov["inferred_components"] != 3 ||
		cov["complete"] != false || len(cov["errors"].([]string)) != 0 {
		t.Errorf("coverage = %v", cov)
	}
	joined := strings.Join(*queries, " ")
	// OSV cannot compare GitHub Actions versions; ranges are checked locally.
	if !strings.Contains(joined, `{"package":{"ecosystem":"PyPI","name":"pydantic"},"version":"2.11.7"}`) ||
		!strings.Contains(joined, `{"package":{"ecosystem":"GitHub Actions","name":"actions/checkout"}}`) {
		t.Errorf("queries = %v", *queries)
	}
}

func TestLoadSBOMUnresolvableRefsStayUncheckedAndVisible(t *testing.T) {
	client, queries := recordingOSV(t, nil) // every registry request 404s
	doc := `{"bomFormat": "CycloneDX", "components": [
		{"name": "pydantic", "purl": "pkg:pypi/pydantic"},
		{"name": "pypa/gh-action-pypi-publish", "version": "release/v1",
		 "purl": "pkg:githubactions/pypa/gh-action-pypi-publish@release%2Fv1"}]}`
	result, err := LoadFile(context.Background(), writeTemp(t, "bom.json", doc), "", nil, client)
	if err != nil {
		t.Fatal(err)
	}
	cov := result.Coverage
	errs := strings.Join(cov["errors"].([]string), " ")
	if cov["queried_components"] != 0 || cov["unqueryable_components"] != 2 || cov["inferred_components"] != 0 ||
		len(*queries) != 0 || !strings.Contains(errs, "pydantic (no version): PyPI lookup failed") ||
		!strings.Contains(errs, "release/v1") || !strings.Contains(errs, "not a version range") {
		t.Errorf("coverage = %v", cov)
	}
}

func TestLoadSBOMBatchFailureIsIncomplete(t *testing.T) {
	client, _ := fakeOSV(t, loadOSVResponses(t), func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	result, err := LoadFile(context.Background(), filepath.Join("../../testdata", "sbom_spdx.json"), "", nil, client)
	if err != nil {
		t.Fatal(err)
	}
	cov := result.Coverage
	if cov["failed_components"] != 2 || cov["queried_components"] != 0 || cov["complete"] != false ||
		!strings.HasPrefix(cov["errors"].([]string)[0], "Server error '500 Internal Server Error'") {
		t.Errorf("coverage = %v", cov)
	}
}

func TestLoadSBOMShortBatchIsIncomplete(t *testing.T) {
	client, _ := fakeOSV(t, loadOSVResponses(t), func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"results": [{}]}`))
	})
	result, err := LoadFile(context.Background(), filepath.Join("../../testdata", "sbom_spdx.json"), "", nil, client)
	if err != nil {
		t.Fatal(err)
	}
	cov := result.Coverage
	if cov["failed_components"] != 2 || cov["complete"] != false ||
		cov["errors"].([]string)[0] != "OSV querybatch returned 1 result(s) for 2 queries" {
		t.Errorf("coverage = %v", cov)
	}
}

func TestLoadSBOMEmptyResultsAreComplete(t *testing.T) {
	client, _ := fakeOSV(t, loadOSVResponses(t), func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"results": [{}, {}]}`))
	})
	result, err := LoadFile(context.Background(), filepath.Join("../../testdata", "sbom_spdx.json"), "", nil, client)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 || result.Coverage["complete"] != true || result.Coverage["queried_components"] != 2 {
		t.Errorf("coverage = %v", result.Coverage)
	}
}

func TestLoadSBOMDropsActionAdvisoriesOutsideRange(t *testing.T) {
	advisory := func(id, fixed string) json.RawMessage {
		return json.RawMessage(`{"id": "` + id + `", "aliases": [], "affected": [{"package":
			{"name": "tj-actions/changed-files", "ecosystem": "GitHub Actions"},
			"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "` + fixed + `"}]}]}]}`)
	}
	responses := osvResponses{
		Queries: map[string][]string{"GitHub Actions:tj-actions/changed-files@": {"GHSA-IN", "GHSA-OUT"}},
		Vulns:   map[string]json.RawMessage{"GHSA-IN": advisory("GHSA-IN", "46.0.1"), "GHSA-OUT": advisory("GHSA-OUT", "40.0.0")},
	}
	client, _ := fakeOSV(t, responses, nil)
	doc := `{"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "packages": [{
		"name": "tj-actions/changed-files", "SPDXID": "SPDXRef-a", "versionInfo": "45.0.9",
		"externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
		"referenceLocator": "pkg:githubactions/tj-actions/changed-files@45.0.9"}]}]}`
	result, err := LoadFile(context.Background(), writeTemp(t, "actions.spdx.json", doc), "", nil, client)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 || result.Findings[0].VulnID != "GHSA-IN" {
		t.Errorf("findings = %+v", result.Findings)
	}
}

func TestOSVDetailCacheAndValidation(t *testing.T) {
	responses := loadOSVResponses(t)
	responses.Vulns["PYSEC-2021-98"] = json.RawMessage(`{"id": "OSV-DIFFERENT"}`)
	client, details := fakeOSV(t, responses, nil)
	path := filepath.Join("../../testdata", "sbom_spdx.json")
	first, err := LoadFile(context.Background(), path, "", nil, client)
	if err != nil {
		t.Fatal(err)
	}
	errs := strings.Join(first.Coverage["errors"].([]string), "\n")
	if !strings.Contains(errs, "PYSEC-2021-98: OSV returned a vulnerability record that does not match PYSEC-2021-98 (received 'OSV-DIFFERENT')") {
		t.Errorf("mismatched record not rejected: %s", errs)
	}
	calls := atomic.LoadInt32(details)
	if _, err := LoadFile(context.Background(), path, "", nil, client); err != nil {
		t.Fatal(err)
	}
	// Only the two failures are fetched again; successes come from the cache.
	if again := atomic.LoadInt32(details) - calls; again != 2 {
		t.Errorf("second run fetched %d details, want 2 (failures are never cached)", again)
	}
	other := *client
	other.CacheDir = t.TempDir()
	before := atomic.LoadInt32(details)
	if _, err := LoadFile(context.Background(), path, "", nil, &other); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(details)-before != calls {
		t.Error("a different cache directory must not see another directory's cache")
	}
}

func TestLoadSBOMWithoutComponentsFails(t *testing.T) {
	client, _ := fakeOSV(t, loadOSVResponses(t), nil)
	_, err := LoadFile(context.Background(), writeTemp(t, "empty.json", `{"bomFormat": "CycloneDX", "components": []}`), "", nil, client)
	if err == nil || !strings.Contains(err.Error(), "SBOM parsed but contained no components") {
		t.Errorf("err = %v", err)
	}
}

func TestLoadSBOMDefaultAssetAndOverride(t *testing.T) {
	client, _ := fakeOSV(t, loadOSVResponses(t), nil)
	asset := model.NewAsset("payments")
	result, err := LoadFile(context.Background(), filepath.Join("../../testdata", "sbom_spdx.json"), "", &asset, client)
	if err != nil {
		t.Fatal(err)
	}
	if result.Findings[0].Asset.Identifier != "payments" {
		t.Errorf("asset override ignored: %+v", result.Findings[0].Asset)
	}
}
