package enrich

// Authoritative vendor advisory enrichment. The adapters normalize public
// feeds into model.VendorAdvisory. Advisory presence, affected products and
// fixed releases are evidence for an operator; an Exploit-DB entry is public
// PoC evidence for SSVC Exploitation. Exploit-DB is searched live on every
// run and never written to disk.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/d01ki/PatchTriage-go/internal/model"
)

const (
	msrcGuideURL       = "https://msrc.microsoft.com/update-guide/vulnerability/"
	exploitDBMaxResult = 10
	perCVEConcurrency  = 4
	maxVendorCVEs      = 50
	debianMaxBytes     = 512 << 20 // the tracker is one large document
)

// AllSources lists every vendor connector in display order.
var AllSources = []string{"msrc", "rhsa", "usn", "debian", "ghsa", "exploitdb"}

// Queried for every CVE under "auto".
var alwaysSources = []string{"rhsa", "msrc", "exploitdb"}

var appEcosystems = map[string]bool{
	"npm": true, "pypi": true, "maven": true, "nuget": true, "golang": true, "go": true, "rubygems": true,
	"gem": true, "cargo": true, "rust": true, "composer": true, "packagist": true, "pub": true, "hex": true,
	"erlang": true, "actions": true, "github actions": true, "swift": true,
}

// ---------------------------------------------------------- loose JSON

// The feeds are untrusted third-party JSON read with Python-dict tolerance.

func decodeLoose(raw []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	return v, d.Decode(&v)
}

func obj(v any) map[string]any { m, _ := v.(map[string]any); return m }
func arr(v any) []any          { a, _ := v.([]any); return a }

func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case json.Number:
		f, _ := x.Float64()
		return f != 0
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

// str renders a value like Python's str().
func str(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case string:
		return x
	case bool:
		if x {
			return "True"
		}
		return "False"
	}
	return fmt.Sprint(v)
}

// or returns str() of the first truthy value, else fallback.
func or(fallback string, values ...any) string {
	for _, v := range values {
		if truthy(v) {
			return str(v)
		}
	}
	return fallback
}

func uniqueNonEmpty(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range values {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func advisory(source, id, title, link, severity, published string, products, fixed, functions []string) model.VendorAdvisory {
	nonNil := func(v []string) []string {
		if v == nil {
			return []string{}
		}
		return v
	}
	return model.VendorAdvisory{Source: source, AdvisoryID: id, Title: title, URL: link, Severity: severity,
		PublishedAt: published, Products: nonNil(products), FixedVersions: nonNil(fixed), VulnerableFunctions: nonNil(functions)}
}

// ---------------------------------------------------------- parsers

func parseMSRC(raw []byte, cve string) ([]model.VendorAdvisory, error) {
	payload, err := decodeLoose(raw)
	if err != nil {
		return nil, err
	}
	out := []model.VendorAdvisory{}
	for _, row := range arr(obj(payload)["value"]) {
		r := obj(row)
		if r == nil {
			continue
		}
		out = append(out, advisory("msrc", or(cve, r["ID"], r["Alias"]), or("", r["DocumentTitle"]),
			msrcGuideURL+cve, "", or("", r["InitialReleaseDate"]), nil, nil, nil))
	}
	return out, nil
}

func parseRHSA(raw []byte, cve string) ([]model.VendorAdvisory, error) {
	payload, err := decodeLoose(raw)
	if err != nil {
		return nil, err
	}
	rows, isList := payload.([]any)
	if !isList {
		m := obj(payload)
		if m == nil {
			return nil, valueError("Red Hat returned an unexpected response")
		}
		rows = arr(m["data"])
	}
	out := []model.VendorAdvisory{}
	for _, row := range rows {
		r := obj(row)
		listed := false
		for _, id := range arr(r["CVEs"]) {
			listed = listed || id == cve
		}
		if r == nil || !listed {
			continue
		}
		id := or(cve, r["RHSA"], r["advisory"])
		var packages []string
		for _, p := range arr(r["released_packages"]) {
			packages = append(packages, str(p))
		}
		out = append(out, advisory("rhsa", id, "Red Hat Security Advisory "+id, "https://access.redhat.com/errata/"+id,
			or("", r["severity"]), or("", r["released_on"]), packages, packages, nil))
	}
	return out, nil
}

func parseUSN(raw []byte, cve string) ([]model.VendorAdvisory, error) {
	payload, err := decodeLoose(raw)
	if err != nil {
		return nil, err
	}
	p := obj(payload)
	if p == nil || !truthy(p["id"]) {
		return []model.VendorAdvisory{}, nil
	}
	var related, advisoryURLs, products, fixed []string
	for _, v := range arr(p["related"]) {
		if strings.HasPrefix(strings.ToUpper(str(v)), "USN-") {
			related = append(related, str(v))
		}
	}
	for _, ref := range arr(p["references"]) {
		if u := obj(ref)["url"]; truthy(u) && strings.Contains(str(u), "/security/notices/") {
			advisoryURLs = append(advisoryURLs, str(u))
		}
	}
	for _, item := range arr(p["affected"]) {
		i := obj(item)
		if i == nil {
			continue
		}
		name := ""
		if n, ok := obj(i["package"])["name"]; ok {
			name = str(n)
		}
		products = append(products, name)
		for _, versionRange := range arr(i["ranges"]) {
			for _, event := range arr(obj(versionRange)["events"]) {
				if f := obj(event)["fixed"]; truthy(f) {
					fixed = append(fixed, strings.TrimSpace(name+" "+str(f)))
				}
			}
		}
	}
	ids := related
	if len(ids) == 0 {
		ids = []string{"UBUNTU-" + cve}
	}
	out := []model.VendorAdvisory{}
	for index, id := range ids {
		link := ""
		for _, u := range advisoryURLs {
			if strings.Contains(strings.ToLower(u), strings.ToLower(id)) {
				link = u
				break
			}
		}
		if link == "" && strings.HasPrefix(id, "USN-") {
			link = "https://ubuntu.com/security/notices/" + id
		}
		if link == "" && index < len(advisoryURLs) {
			link = advisoryURLs[index]
		}
		out = append(out, advisory("usn", id, or(cve, p["summary"], p["details"]), link, "",
			or("", p["published"]), uniqueNonEmpty(products), uniqueNonEmpty(fixed), nil))
	}
	return out, nil
}

// OrderedKeys returns an object's members in document order (Python dicts
// keep insertion order; the products list depends on it).
func OrderedKeys(raw []byte) ([]string, map[string]json.RawMessage) {
	var members map[string]json.RawMessage
	if json.Unmarshal(raw, &members) != nil {
		return nil, nil
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	var keys []string
	if tok, err := d.Token(); err != nil || tok != json.Delim('{') {
		return nil, nil
	}
	for d.More() {
		tok, err := d.Token()
		if err != nil {
			return nil, nil
		}
		keys = append(keys, tok.(string))
		var skip json.RawMessage
		if d.Decode(&skip) != nil {
			return nil, nil
		}
	}
	return keys, members
}

// debianDocument is the tracker JSON with its package order.
type debianDocument struct {
	order    []string
	packages map[string]json.RawMessage
}

func parseDebianDocument(raw []byte) (debianDocument, error) {
	order, packages := OrderedKeys(raw)
	if packages == nil {
		return debianDocument{}, valueError("Debian Security Tracker returned an unexpected document")
	}
	return debianDocument{order: order, packages: packages}, nil
}

func parseDebian(raw []byte, cve string) ([]model.VendorAdvisory, error) {
	doc, err := parseDebianDocument(raw)
	if err != nil {
		return nil, err
	}
	return doc.advisories(cve), nil
}

func (doc debianDocument) advisories(cve string) []model.VendorAdvisory {
	var products, fixed, descriptions, severities []string
	for _, pkg := range doc.order {
		var records map[string]json.RawMessage
		if json.Unmarshal(doc.packages[pkg], &records) != nil {
			continue
		}
		recordRaw, ok := records[cve]
		if !ok {
			continue
		}
		record, _ := decodeLoose(recordRaw)
		r := obj(record)
		if truthy(r["description"]) {
			descriptions = append(descriptions, str(r["description"]))
		}
		order, _ := OrderedKeys(objectRaw(recordRaw, "releases"))
		releases := obj(r["releases"])
		for _, release := range order {
			state := obj(releases[release])
			if state == nil {
				continue
			}
			products = append(products, fmt.Sprintf("%s (%s: %s)", pkg, release, or("unknown", state["status"])))
			if version := or("", state["fixed_version"]); version != "" && version != "0" {
				fixed = append(fixed, fmt.Sprintf("%s %s: %s", pkg, release, version))
			}
			if truthy(state["urgency"]) {
				severities = append(severities, str(state["urgency"]))
			}
		}
	}
	if len(products) == 0 {
		return []model.VendorAdvisory{}
	}
	title, severity := "Debian Security Tracker: "+cve, ""
	if len(descriptions) > 0 {
		title = descriptions[0]
	}
	if len(severities) > 0 {
		severity = severities[0]
	}
	return []model.VendorAdvisory{advisory("debian", cve, title, "https://security-tracker.debian.org/tracker/"+cve,
		severity, "", uniqueNonEmpty(products), uniqueNonEmpty(fixed), nil)}
}

func objectRaw(raw []byte, key string) []byte {
	var members map[string]json.RawMessage
	_ = json.Unmarshal(raw, &members)
	return members[key]
}

func parseGHSA(raw []byte, cve string) ([]model.VendorAdvisory, error) {
	payload, err := decodeLoose(raw)
	if err != nil {
		return nil, err
	}
	out := []model.VendorAdvisory{}
	for _, row := range arr(payload) {
		r := obj(row)
		if r == nil {
			continue
		}
		var products, fixed, functions []string
		for _, v := range arr(r["vulnerabilities"]) {
			vuln := obj(v)
			if vuln == nil {
				continue
			}
			pkg := obj(vuln["package"])
			name, ecosystem := or("", pkg["name"]), or("", pkg["ecosystem"])
			products = append(products, strings.Trim(ecosystem+":"+name, ":"))
			patched := ""
			if p, isMap := vuln["first_patched_version"].(map[string]any); isMap {
				patched = or("", p["identifier"])
			} else {
				patched = or("", vuln["first_patched_version"])
			}
			if patched != "" {
				fixed = append(fixed, strings.TrimSpace(name+" "+patched))
			}
			for _, fn := range arr(vuln["vulnerable_functions"]) {
				functions = append(functions, str(fn))
			}
		}
		out = append(out, advisory("ghsa", or(cve, r["ghsa_id"]), or(cve, r["summary"], r["description"]),
			or("", r["html_url"]), or("", r["severity"]), or("", r["published_at"]),
			uniqueNonEmpty(products), uniqueNonEmpty(fixed), uniqueNonEmpty(functions)))
	}
	return out, nil
}

func truncateRunes(s string, n int) string {
	runes := []rune(s)
	if len(runes) > n {
		return string(runes[:n])
	}
	return s
}

// parseExploitDB normalizes an Exploit-DB search response, keeping only
// rows whose CVE code matches exactly.
func parseExploitDB(raw []byte, cve string) ([]model.VendorAdvisory, error) {
	payload, err := decodeLoose(raw)
	if err != nil {
		return nil, err
	}
	rows, ok := obj(payload)["data"].([]any)
	if !ok {
		return nil, valueError("Exploit-DB returned an unexpected search response")
	}
	number := strings.TrimPrefix(strings.ToUpper(cve), "CVE-")
	out := []model.VendorAdvisory{}
	for _, row := range rows[:min(len(rows), exploitDBMaxResult)] {
		r := obj(row)
		if r == nil {
			continue
		}
		id := strings.TrimSpace(or("", r["id"]))
		matched := false
		for _, code := range arr(r["code"]) {
			c := obj(code)
			matched = matched || (c["code_type"] == "cve" && strings.TrimPrefix(strings.ToUpper(or("", c["code"])), "CVE-") == number)
		}
		if !isDigits(id) || !matched {
			continue
		}
		description := r["description"]
		if list, isList := description.([]any); isList {
			description = ""
			if len(list) > 0 {
				description = list[len(list)-1]
			}
		}
		var products []string
		for _, p := range []string{or("", obj(r["platform"])["platform"]), or("", obj(r["type"])["display"])} {
			if p != "" {
				products = append(products, p)
			}
		}
		severity := "unverified"
		if str(r["verified"]) == "1" {
			severity = "verified"
		}
		out = append(out, advisory("exploitdb", "EDB-"+id, truncateRunes(or("", description), 300),
			"https://www.exploit-db.com/exploits/"+id, severity, or("", r["date_published"]), products, nil, nil))
	}
	return out, nil
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

// ---------------------------------------------------------- selection

// ParseSources validates a vendor source selection: auto, all, or a list.
func ParseSources(value string) ([]string, error) {
	var requested []string
	for _, v := range strings.Split(value, ",") {
		if v = strings.ToLower(strings.TrimSpace(v)); v != "" {
			requested = append(requested, v)
		}
	}
	if len(requested) == 1 && requested[0] == "all" {
		return append([]string{}, AllSources...), nil
	}
	if contains(requested, "auto") && len(requested) != 1 {
		return nil, valueError("auto cannot be combined with explicit vendor sources")
	}
	var unknown []string
	for _, v := range requested {
		if v != "auto" && !contains(AllSources, v) {
			unknown = append(unknown, v)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return nil, valueError(fmt.Sprintf("unknown vendor source(s): %s; choose auto, all, or %s",
			strings.Join(unknown, ", "), strings.Join(AllSources, ",")))
	}
	if len(requested) == 0 {
		requested = []string{"auto"}
	}
	return uniqueNonEmpty(requested), nil
}

// AutoSources picks the connectors relevant to one finding.
func AutoSources(f *model.Finding) []string {
	ecosystem, purl := strings.ToLower(f.Package.Ecosystem), strings.ToLower(f.Package.Purl)
	haystack := strings.Join([]string{ecosystem, purl, strings.ToLower(f.Asset.Kind)}, " ")
	has := func(needles ...string) bool {
		for _, n := range needles {
			if strings.Contains(haystack, n) {
				return true
			}
		}
		return false
	}
	var sources []string
	if has("windows", "microsoft", "nuget", "dotnet", "powershell") {
		sources = append(sources, "msrc")
	}
	if has("redhat", "rhel") {
		sources = append(sources, "rhsa")
	}
	if has("ubuntu") {
		sources = append(sources, "usn")
	}
	if has("debian", "pkg:deb/debian/", "dpkg") {
		sources = append(sources, "debian")
	}
	distro := strings.Contains(purl, "pkg:deb/") || strings.Contains(purl, "pkg:rpm/") || strings.Contains(purl, "pkg:apk/")
	if appEcosystems[ecosystem] || (strings.HasPrefix(purl, "pkg:") && !distro) {
		sources = append(sources, "ghsa")
	}
	if !contains(sources, "usn") && !contains(sources, "debian") && !contains(sources, "ghsa") {
		sources = append(sources, "ghsa")
	}
	return uniqueNonEmpty(append(append([]string{}, alwaysSources...), sources...))
}

// ---------------------------------------------------------- fetching

func (c *client) fetchVendor(ctx context.Context, source, cve, token string) ([]model.VendorAdvisory, error) {
	var target string
	headers := map[string]string{"Accept": "application/json"}
	parse := map[string]func([]byte, string) ([]model.VendorAdvisory, error){
		"exploitdb": parseExploitDB, "msrc": parseMSRC, "usn": parseUSN, "ghsa": parseGHSA,
	}[source]
	switch source {
	case "exploitdb":
		target = c.urls.ExploitDB + "?" + url.Values{"cve": {strings.TrimPrefix(strings.ToUpper(cve), "CVE-")},
			"draw": {"1"}, "start": {"0"}, "length": {fmt.Sprint(exploitDBMaxResult)}}.Encode()
		headers["X-Requested-With"] = "XMLHttpRequest"
	case "msrc":
		target = c.urls.MSRC + cve
	case "usn":
		target = c.urls.UbuntuOSV + cve
	case "ghsa":
		target = c.urls.GHSA + "?cve_id=" + url.QueryEscape(cve)
		headers = map[string]string{"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
			"User-Agent": "patchtriage/0.6"}
		if token != "" {
			headers["Authorization"] = "Bearer " + token
		}
	default:
		return nil, valueError(source + " is not a per-CVE source")
	}
	resp, body, err := c.get(ctx, c.http, target, headers, 30*time.Second, MaxResponseBytes)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound && (source == "msrc" || source == "usn") {
		return []model.VendorAdvisory{}, nil // the vendor has no record for it
	}
	if err := StatusError(resp); err != nil {
		return nil, err
	}
	return parse(body, cve)
}

type vendorCache map[string]map[string][]model.VendorAdvisory

func (c *client) debianDocument(ctx context.Context) (debianDocument, error) {
	path := filepath.Join(c.dir, "debian_security_tracker.json")
	cacheLock.Lock()
	info, statErr := os.Stat(path)
	var cached []byte
	if statErr == nil && time.Since(info.ModTime()) < 24*time.Hour {
		cached, _ = os.ReadFile(path)
	}
	cacheLock.Unlock()
	if cached != nil {
		if doc, err := parseDebianDocument(cached); err == nil {
			return doc, nil
		}
	}
	resp, body, err := c.get(ctx, c.http, c.urls.Debian, nil, 120*time.Second, debianMaxBytes)
	if err != nil {
		return debianDocument{}, err
	}
	if err := StatusError(resp); err != nil {
		return debianDocument{}, err
	}
	doc, err := parseDebianDocument(body)
	if err != nil {
		return debianDocument{}, err
	}
	cacheLock.Lock()
	_ = atomicWriteJSON(path, json.RawMessage(body))
	cacheLock.Unlock()
	return doc, nil
}

func cvssOrZero(f *model.Finding) float64 {
	if f.Enrichment.NVDCVSSScore != nil && *f.Enrichment.NVDCVSSScore != 0 {
		return *f.Enrichment.NVDCVSSScore
	}
	if f.CVSSScore != nil {
		return *f.CVSSScore
	}
	return 0
}

// enrichVendors attaches official vendor records in place; source failures
// are recorded per finding and never abort the run.
func enrichVendors(ctx context.Context, findings []*model.Finding, o Options) (map[string]any, error) {
	requested, err := ParseSources(o.VendorSources)
	if err != nil {
		return nil, err
	}
	auto := len(requested) == 1 && requested[0] == "auto"
	c := o.client()

	// Rank CVEs by KEV, EPSS and CVSS so the lookup limit keeps the most important.
	rank := map[string][3]float64{}
	for _, f := range findings {
		if !strings.HasPrefix(f.VulnID, "CVE-") {
			continue
		}
		kev, epss := 0.0, 0.0
		if f.Enrichment.InCISAKEV {
			kev = 1
		}
		if f.Enrichment.EPSSScore != nil {
			epss = *f.Enrichment.EPSSScore
		}
		key := [3]float64{kev, epss, cvssOrZero(f)}
		if prev, ok := rank[f.VulnID]; !ok || key[0] > prev[0] || (key[0] == prev[0] && (key[1] > prev[1] || (key[1] == prev[1] && key[2] > prev[2]))) {
			rank[f.VulnID] = key
		}
	}
	var ranked []string
	for cve := range rank {
		ranked = append(ranked, cve)
	}
	sort.Slice(ranked, func(i, j int) bool {
		a, b := rank[ranked[i]], rank[ranked[j]]
		for n := range a {
			if a[n] != b[n] {
				return a[n] > b[n]
			}
		}
		return ranked[i] < ranked[j]
	})
	limit := min(len(ranked), maxVendorCVEs)
	selected := map[string]bool{}
	for _, cve := range ranked[:limit] {
		selected[cve] = true
	}
	effective := func(f *model.Finding) []string {
		if auto {
			return AutoSources(f)
		}
		return requested
	}
	sourceCVEs := map[string]map[string]bool{}
	for _, s := range AllSources {
		sourceCVEs[s] = map[string]bool{}
	}
	for _, f := range findings {
		if selected[f.VulnID] {
			for _, s := range effective(f) {
				sourceCVEs[s][f.VulnID] = true
			}
		}
	}
	sortedCVEs := func(source string) []string {
		var out []string
		for cve := range sourceCVEs[source] {
			out = append(out, cve)
		}
		sort.Strings(out)
		return out
	}

	cache := vendorCache{}
	if stored, ok := loadCache(c.dir, "vendor_advisories.json", 24*time.Hour, false); ok {
		for source, raw := range stored {
			var rows map[string][]model.VendorAdvisory
			if json.Unmarshal(raw, &rows) == nil {
				cache[source] = rows
			}
		}
	}
	for _, s := range AllSources {
		if cache[s] == nil {
			cache[s] = map[string][]model.VendorAdvisory{}
		}
	}
	cache["exploitdb"] = map[string][]model.VendorAdvisory{} // live only: never reuse a stored result
	errs := map[[2]string]string{}

	// Red Hat accepts comma-separated CVE batches.
	var missing []string
	for _, cve := range sortedCVEs("rhsa") {
		if _, ok := cache["rhsa"][cve]; !ok {
			missing = append(missing, cve)
		}
	}
	for start := 0; start < len(missing); start += 50 {
		batch := missing[start:min(start+50, len(missing))]
		body, err := c.getJSON(ctx, c.urls.RHSA+"?"+url.Values{"cve": {strings.Join(batch, ",")}, "isCompressed": {"false"}}.Encode(),
			nil, 60*time.Second)
		for _, cve := range batch {
			if err == nil {
				var rows []model.VendorAdvisory
				if rows, err = parseRHSA(body, cve); err == nil {
					cache["rhsa"][cve] = rows
					continue
				}
			}
			errs[[2]string{"rhsa", cve}] = err.Error()
		}
	}

	// Debian publishes one complete tracker document, fetched once a day.
	if len(sourceCVEs["debian"]) > 0 {
		doc, err := c.debianDocument(ctx)
		for _, cve := range sortedCVEs("debian") {
			if err != nil {
				errs[[2]string{"debian", cve}] = err.Error()
			} else {
				cache["debian"][cve] = doc.advisories(cve)
			}
		}
	}

	// Per-CVE lookups run a few at a time.
	token := o.GitHubToken
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	if token == "" {
		token = os.Getenv("GH_TOKEN")
	}
	type job struct{ source, cve string }
	var jobs []job
	for _, source := range []string{"exploitdb", "msrc", "usn", "ghsa"} {
		for _, cve := range sortedCVEs(source) {
			if _, ok := cache[source][cve]; !ok {
				jobs = append(jobs, job{source, cve})
			}
		}
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	slots := make(chan struct{}, perCVEConcurrency)
	for _, j := range jobs {
		wg.Add(1)
		slots <- struct{}{}
		go func(j job) {
			defer wg.Done()
			defer func() { <-slots }()
			rows, err := c.fetchVendor(ctx, j.source, j.cve, token)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs[[2]string{j.source, j.cve}] = err.Error()
				return
			}
			cache[j.source][j.cve] = rows
		}(j)
	}
	wg.Wait()
	persisted := vendorCache{}
	for source, rows := range cache {
		if source != "exploitdb" {
			persisted[source] = rows
		}
	}
	_ = saveCache(c.dir, "vendor_advisories.json", persisted)

	beyondLimit := map[string]bool{}
	for _, cve := range ranked[limit:] {
		beyondLimit[cve] = true
	}
	advisories := 0
	for _, f := range findings {
		e := &f.Enrichment
		if !selected[f.VulnID] {
			if beyondLimit[f.VulnID] {
				e.VendorLookupErrors = append(e.VendorLookupErrors, fmt.Sprintf("vendor: lookup limit %d reached", maxVendorCVEs))
			}
			continue
		}
		for _, source := range effective(f) {
			e.VendorSourcesChecked = appendOnce(e.VendorSourcesChecked, source)
			e.Sources = appendOnce(e.Sources, "vendor:"+source)
			if message, failed := errs[[2]string{source, f.VulnID}]; failed {
				e.VendorLookupErrors = append(e.VendorLookupErrors, source+": "+message)
				continue
			}
			seen := map[[2]string]bool{}
			for _, a := range e.VendorAdvisories {
				seen[[2]string{a.Source, a.AdvisoryID}] = true
			}
			for _, a := range cache[source][f.VulnID] {
				if key := [2]string{a.Source, a.AdvisoryID}; !seen[key] {
					e.VendorAdvisories = append(e.VendorAdvisories, a)
					seen[key] = true
					advisories++
				}
				if source == "exploitdb" && a.URL != "" {
					// A published Exploit-DB entry is public PoC evidence.
					e.ExploitRefs = appendOnce(e.ExploitRefs, a.URL)
				}
			}
			if source == "exploitdb" {
				// The completed search counts as coverage even with no hit.
				e.ExploitSourcesChecked = appendOnce(e.ExploitSourcesChecked, "exploitdb")
			}
		}
	}
	var used []string
	for _, s := range AllSources {
		if len(sourceCVEs[s]) > 0 {
			used = append(used, s)
		}
	}
	if used == nil {
		used = []string{}
	}
	return map[string]any{"sources": used, "checked_cves": len(selected), "advisories": advisories,
		"errors": len(errs), "truncated": len(ranked) - len(selected)}, nil
}
