package ingest

// SBOM ingestion via OSV.dev. An SBOM lists components, not
// vulnerabilities, so components are resolved through the free OSV.dev API.
// Coverage records exactly which components were and were not checked:
// "no findings" from an SBOM whose components could not be queried is not
// a clean result.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/d01ki/PatchTriage-go/internal/enrich"
	"github.com/d01ki/PatchTriage-go/internal/model"
)

const (
	osvBatchSize        = 100
	osvBatchTimeout     = 60 * time.Second
	osvDetailTimeout    = 30 * time.Second
	osvCacheMaxAge      = 7 * 24 * time.Hour
	osvCacheFile        = "osv_vulns.json"
	defaultOSVBaseURL   = "https://api.osv.dev"
	maxUnqueryableNames = 50
)

// osvEcosystems maps model.NormalizeEcosystem values to OSV's names.
var osvEcosystems = map[string]string{
	"pypi": "PyPI", "golang": "Go", "npm": "npm", "maven": "Maven", "nuget": "NuGet",
	"rubygems": "RubyGems", "crates.io": "crates.io", "packagist": "Packagist",
	"githubactions": "GitHub Actions",
}

// OSV's query API does not compare versions for these ecosystems: query the
// package alone and evaluate the ranges locally.
var localRangeEcosystems = map[string]bool{"GitHub Actions": true}

// NewOSVClient returns a client for api.osv.dev caching details in cacheDir.
func NewOSVClient(cacheDir string) *OSVClient {
	return &OSVClient{HTTP: &http.Client{}, BaseURL: defaultOSVBaseURL, CacheDir: cacheDir}
}

// IsSBOM returns "cyclonedx" or "spdx" when the JSON looks like an SBOM.
func IsSBOM(raw []byte) string {
	fields, ok := objectFields(raw)
	if !ok {
		return ""
	}
	_, hasComponents := fields["components"]
	if flexText(fields["bomFormat"]) == "CycloneDX" || (hasComponents && flexText(fields["specVersion"]) != "") {
		return "cyclonedx"
	}
	_, hasID := fields["SPDXID"]
	_, hasPackages := fields["packages"]
	var version string
	_ = json.Unmarshal(fields["spdxVersion"], &version)
	if strings.HasPrefix(version, "SPDX-") || (hasID && hasPackages) {
		return "spdx"
	}
	return ""
}

// isConcrete reports whether value is a release identifier OSV can match,
// not a range, wildcard or branch ref.
func isConcrete(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, "*<>=~^|, /") || !strings.ContainsFunc(value, unicode.IsDigit) {
		return false
	}
	for _, part := range strings.Split(value, ".") {
		if part == "x" || part == "X" { // npm/GitHub wildcard syntax
			return false
		}
	}
	return true
}

func objects(raw json.RawMessage) []map[string]json.RawMessage {
	var items []json.RawMessage
	_ = json.Unmarshal(raw, &items)
	var out []map[string]json.RawMessage
	for _, item := range items {
		if fields, ok := objectFields(item); ok {
			out = append(out, fields)
		}
	}
	return out
}

func purlType(purl string) string {
	typ, _, _, _ := model.ParsePurl(purl)
	return typ
}

func cyclonedxComponents(fields map[string]json.RawMessage) []model.Package {
	var out []model.Package
	var walk func(json.RawMessage)
	walk = func(raw json.RawMessage) {
		for _, c := range objects(raw) {
			if name := flexText(c["name"]); name != "" {
				purl := flexText(c["purl"])
				out = append(out, model.Package{Name: name, Version: flexText(c["version"]), Purl: purl, Ecosystem: purlType(purl)})
			}
			walk(c["components"]) // CycloneDX allows nested components
		}
	}
	walk(fields["components"])
	return out
}

func spdxPurl(pkg map[string]json.RawMessage) string {
	for _, ref := range objects(pkg["externalRefs"]) {
		category := flexText(ref["referenceCategory"])
		if flexText(ref["referenceType"]) == "purl" || category == "PACKAGE-MANAGER" || category == "PACKAGE_MANAGER" {
			if locator := flexText(ref["referenceLocator"]); strings.HasPrefix(locator, "pkg:") {
				return locator
			}
		}
	}
	return ""
}

func spdxComponents(fields map[string]json.RawMessage) []model.Package {
	// The described package is the SBOM's subject (GitHub records the
	// repository itself at a branch), not a dependency.
	described := map[string]bool{}
	var describes []string
	_ = json.Unmarshal(fields["documentDescribes"], &describes)
	for _, id := range describes {
		described[id] = true
	}
	documentID := "SPDXRef-DOCUMENT"
	if _, ok := fields["SPDXID"]; ok {
		documentID = flexText(fields["SPDXID"])
	}
	for _, r := range objects(fields["relationships"]) {
		if flexText(r["relationshipType"]) == "DESCRIBES" && flexText(r["spdxElementId"]) == documentID {
			described[flexText(r["relatedSpdxElement"])] = true
		}
	}
	var out []model.Package
	for _, p := range objects(fields["packages"]) {
		name := flexText(p["name"])
		if name == "" {
			continue
		}
		version := flexText(p["versionInfo"])
		if described[flexText(p["SPDXID"])] && !isConcrete(version) {
			continue
		}
		purl := spdxPurl(p)
		out = append(out, model.Package{Name: name, Version: version, Purl: purl, Ecosystem: purlType(purl)})
	}
	return out
}

// ParseSBOMComponents lists the components of a CycloneDX or SPDX SBOM.
func ParseSBOMComponents(raw []byte) ([]model.Package, error) {
	fields, _ := objectFields(raw)
	switch IsSBOM(raw) {
	case "cyclonedx":
		return cyclonedxComponents(fields), nil
	case "spdx":
		return spdxComponents(fields), nil
	}
	return nil, fmt.Errorf("not a recognized CycloneDX or SPDX SBOM")
}

func osvEcosystem(value string) string {
	if name, ok := osvEcosystems[model.NormalizeEcosystem(value)]; ok {
		return name
	}
	return value
}

// osvName turns pkg:npm/%40scope/ui into @scope/ui; else the component name.
func osvName(c model.Package) string {
	_, namespace, name, _ := model.ParsePurl(c.Purl)
	switch {
	case namespace != "" && name != "":
		return namespace + "/" + name
	case name != "":
		return name
	case namespace != "":
		return namespace
	}
	return c.Name
}

// componentQuery is the OSV query for one component, or nil without a
// concrete version: a range is not an installed version, and OSV would
// match it as an opaque string and report nothing.
func componentQuery(c model.Package) map[string]any {
	_, _, _, purlVersion := model.ParsePurl(c.Purl)
	ecosystem := osvEcosystem(c.Ecosystem)
	if c.VersionSource == "" {
		version := purlVersion
		if version == "" {
			version = c.Version
		}
		if !isConcrete(version) {
			return nil
		}
		if c.Purl != "" && !localRangeEcosystems[ecosystem] {
			query := map[string]any{"package": map[string]string{"purl": c.Purl}}
			if purlVersion == "" {
				query["version"] = c.Version
			}
			return query
		}
		if c.Ecosystem == "" || c.Name == "" {
			return nil
		}
	}
	query := map[string]any{"package": map[string]string{"name": osvName(c), "ecosystem": ecosystem}}
	if !localRangeEcosystems[ecosystem] {
		version := c.Version
		if version == "" {
			version = purlVersion
		}
		query["version"] = version
	}
	return query
}

type osvCoverage struct {
	total, queryable, queried, unqueryable, failed int
	ids, resolved, detailFailed                    int
	errors, unqueryableNames                       []string
	queriedEcosystems, unqueryableEcosystems       []string
}

func (c *osvCoverage) complete() bool {
	return c.unqueryable == 0 && c.failed == 0 && c.detailFailed == 0 && c.queried == c.total
}

func (c *osvCoverage) asMap() model.Coverage {
	nonNil := func(v []string) []string {
		if v == nil {
			return []string{}
		}
		return v
	}
	return model.Coverage{
		"source_type": "sbom:osv", "complete": c.complete(),
		"total_components": c.total, "queryable_components": c.queryable,
		"queried_components": c.queried, "unqueryable_components": c.unqueryable,
		"failed_components": c.failed, "vulnerability_ids": c.ids,
		"vulnerability_details_resolved": c.resolved, "vulnerability_details_failed": c.detailFailed,
		"errors": nonNil(c.errors), "unqueryable_names": nonNil(c.unqueryableNames),
		"queried_ecosystems": nonNil(c.queriedEcosystems), "unqueryable_ecosystems": nonNil(c.unqueryableEcosystems),
		"inferred_components": 0, "inferred_versions": []map[string]string{},
	}
}

// SortedNonEmpty returns the sorted set of non-empty values.
func SortedNonEmpty(values []string) []string {
	var out []string
	for _, v := range unique(values) {
		if v != "" {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

func (c *OSVClient) do(ctx context.Context, method, url string, body []byte, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "patchtriage")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := enrich.StatusError(resp); err != nil {
		return nil, err
	}
	return enrich.ReadBody(resp)
}

// queryBatch resolves vulnerability ids for one chunk of queries. OSV must
// return exactly one result per query; anything else fails the whole chunk
// rather than assigning ids to the wrong package.
func (c *OSVClient) queryBatch(ctx context.Context, queries []map[string]any) ([][]string, error) {
	body, _ := json.Marshal(map[string]any{"queries": queries})
	raw, err := c.do(ctx, http.MethodPost, c.BaseURL+"/v1/querybatch", body, osvBatchTimeout)
	if err != nil {
		return nil, err
	}
	var response struct {
		Results []json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(raw, &response); err != nil || response.Results == nil {
		return nil, fmt.Errorf("OSV querybatch returned invalid result(s) for %d queries", len(queries))
	}
	if len(response.Results) != len(queries) {
		return nil, fmt.Errorf("OSV querybatch returned %d result(s) for %d queries", len(response.Results), len(queries))
	}
	ids := make([][]string, len(queries))
	for i, result := range response.Results {
		fields, ok := objectFields(result)
		if !ok {
			return nil, fmt.Errorf("OSV querybatch returned a non-object result")
		}
		var vulns []json.RawMessage
		if v := bytes.TrimSpace(fields["vulns"]); len(v) > 0 && !bytes.Equal(v, []byte("null")) {
			if json.Unmarshal(v, &vulns) != nil {
				return nil, fmt.Errorf("OSV querybatch returned invalid vulnerabilities")
			}
		}
		var found []string
		for _, v := range vulns {
			if vf, ok := objectFields(v); ok {
				if id := flexText(vf["id"]); id != "" {
					found = append(found, id)
				}
			}
		}
		ids[i] = unique(found)
	}
	return ids, nil
}

func validRecord(raw json.RawMessage, id string) (string, bool) {
	fields, ok := objectFields(raw)
	if !ok {
		return "", false
	}
	var got string
	if json.Unmarshal(fields["id"], &got) != nil || got == "" {
		return "", false
	}
	return got, got == id
}

// fetchVuln returns one validated record; failures are never cached.
func (c *OSVClient) fetchVuln(ctx context.Context, id string, cache, updates map[string]json.RawMessage) (OSVVuln, error) {
	raw, ok := cache[id]
	if _, valid := validRecord(raw, id); !ok || !valid {
		delete(cache, id)
		fetched, err := c.do(ctx, http.MethodGet, c.BaseURL+"/v1/vulns/"+id, nil, osvDetailTimeout)
		if err != nil {
			return OSVVuln{}, err
		}
		got, valid := validRecord(fetched, id)
		if !valid {
			detail := ""
			if got != "" {
				detail = fmt.Sprintf(" (received '%s')", got)
			}
			return OSVVuln{}, fmt.Errorf("OSV returned a vulnerability record that does not match %s%s", id, detail)
		}
		raw = fetched
		cache[id], updates[id] = fetched, fetched
	}
	var vuln OSVVuln
	if err := json.Unmarshal(raw, &vuln); err != nil {
		return OSVVuln{}, err
	}
	return vuln, nil
}

// rawFromOSVVuln maps one OSV record onto a RawFinding.
func rawFromOSVVuln(v OSVVuln, pkg model.Package, asset model.Asset, now time.Time) model.RawFinding {
	vulnID, aliases := preferCVE(v.ID, v.Aliases)
	label := v.DatabaseSpecific.Severity
	for _, a := range v.Affected {
		if label != "" {
			break
		}
		label = a.DatabaseSpecific.Severity
	}
	withFix := pkg
	withFix.FixedVersion = SelectOSVFixedVersion(v, pkg)
	return model.RawFinding{
		VulnID: vulnID, Aliases: aliases, SourceScanner: "osv-sbom", Package: withFix, Asset: asset,
		Severity: model.ParseSeverity(label), Title: v.Summary, Description: truncate(v.Details, 2000),
		References: referenceURLs(v), DetectedAt: now,
	}
}

func loadSBOM(ctx context.Context, raw []byte, path string, asset *model.Asset, c *OSVClient) (LoadResult, error) {
	components, err := ParseSBOMComponents(raw)
	if err != nil {
		return LoadResult{}, err
	}
	fields, _ := objectFields(raw)
	if len(components) == 0 && len(objects(fields["packages"])) == 0 {
		// An SPDX document listing only its own subject is an empty result.
		return LoadResult{}, fmt.Errorf("%s: SBOM parsed but contained no components", path)
	}
	if c == nil {
		c = NewOSVClient(enrich.DefaultCacheDir())
	}
	defaultAsset := model.NewAsset(filepath.Base(path))
	defaultAsset.Kind = "sbom"
	if asset != nil {
		defaultAsset = *asset
	}

	cov := &osvCoverage{total: len(components)}
	var queries []map[string]any
	var queryIndex []int
	var checkedEco, skippedEco []string
	for i, component := range components {
		if q := componentQuery(component); q != nil {
			queries, queryIndex = append(queries, q), append(queryIndex, i)
			checkedEco = append(checkedEco, component.Ecosystem)
			continue
		}
		cov.unqueryable++
		skippedEco = append(skippedEco, component.Ecosystem)
		if component.Name != "" && len(cov.unqueryableNames) < maxUnqueryableNames {
			cov.unqueryableNames = append(cov.unqueryableNames, component.Name)
		}
	}
	cov.queryable = len(queries)
	cov.queriedEcosystems, cov.unqueryableEcosystems = SortedNonEmpty(checkedEco), SortedNonEmpty(skippedEco)
	if cov.unqueryable > 0 {
		cov.errors = append(cov.errors, fmt.Sprintf("%d component(s) lacked a queryable package version/purl", cov.unqueryable))
	}

	ids := make([][]string, len(components))
	for start := 0; start < len(queries); start += osvBatchSize {
		end := min(start+osvBatchSize, len(queries))
		chunk, err := c.queryBatch(ctx, queries[start:end])
		if err != nil {
			cov.failed += end - start
			cov.errors = append(cov.errors, err.Error())
			continue
		}
		for offset, found := range chunk {
			ids[queryIndex[start+offset]] = found
		}
		cov.queried += end - start
	}
	for _, group := range ids {
		cov.ids += len(group)
	}

	cache := enrich.LoadEntryCache(c.CacheDir, osvCacheFile, osvCacheMaxAge)
	updates := map[string]json.RawMessage{}
	failed := map[string]bool{}
	now := time.Now().UTC()
	var findings []model.RawFinding
	for i, component := range components {
		for _, id := range ids[i] {
			if failed[id] {
				cov.detailFailed++
				continue
			}
			vuln, err := c.fetchVuln(ctx, id, cache, updates)
			if err != nil {
				failed[id] = true
				cov.detailFailed++
				cov.errors = append(cov.errors, id+": "+err.Error())
				continue
			}
			cov.resolved++
			if localRangeEcosystems[osvEcosystem(component.Ecosystem)] && !OSVAffects(vuln, component) {
				continue
			}
			findings = append(findings, rawFromOSVVuln(vuln, component, defaultAsset, now))
		}
	}
	_ = enrich.MergeEntryCache(c.CacheDir, osvCacheFile, updates) // a cache write failure never fails the run
	return LoadResult{Findings: findings, Coverage: cov.asMap()}, nil
}
