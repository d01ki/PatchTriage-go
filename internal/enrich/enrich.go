// Package enrich attaches authoritative, deterministic evidence (EPSS, CISA
// KEV, CISA Vulnrichment, NVD and vendor advisories) to findings. Values are
// fetched, never generated; failures are recorded, never read as absence.
package enrich

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/d01ki/PatchTriage-go/data"
	"github.com/d01ki/PatchTriage-go/internal/model"
)

const (
	entryCacheSchema = "patchtriage-entry-cache-v1"
	// MaxResponseBytes bounds every provider response.
	MaxResponseBytes = 32 << 20
)

var cacheLock sync.Mutex

// DefaultCacheDir honors PATCHTRIAGE_CACHE_DIR, else ~/.cache/patchtriage-go
// (kept apart from the Python implementation's cache).
func DefaultCacheDir() string {
	if dir := os.Getenv("PATCHTRIAGE_CACHE_DIR"); dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "patchtriage-go-cache")
	}
	return filepath.Join(home, ".cache", "patchtriage-go")
}

func atomicWriteJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if _, err := temp.Write(raw); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(temp.Name(), path)
}

type cacheEntry struct {
	Value     json.RawMessage `json:"value"`
	FetchedAt float64         `json:"fetched_at"`
}

func isObject(raw json.RawMessage) bool {
	var fields map[string]json.RawMessage
	return json.Unmarshal(raw, &fields) == nil && fields != nil
}

// decodeEntryCache normalizes timestamped and legacy (value-only) caches.
func decodeEntryCache(raw []byte, fallback float64) map[string]cacheEntry {
	entries := map[string]cacheEntry{}
	var top map[string]json.RawMessage
	if json.Unmarshal(raw, &top) != nil {
		return entries
	}
	var schema string
	_ = json.Unmarshal(top["_schema"], &schema)
	if schema == entryCacheSchema {
		var wrapped map[string]json.RawMessage
		if json.Unmarshal(top["entries"], &wrapped) != nil {
			return entries
		}
		for key, item := range wrapped {
			var entry struct {
				Value     json.RawMessage `json:"value"`
				FetchedAt *float64        `json:"fetched_at"`
			}
			if json.Unmarshal(item, &entry) == nil && entry.FetchedAt != nil && isObject(entry.Value) {
				entries[key] = cacheEntry{entry.Value, *entry.FetchedAt}
			}
		}
		return entries
	}
	for key, value := range top {
		if isObject(value) {
			entries[key] = cacheEntry{value, fallback}
		}
	}
	return entries
}

func unixSeconds(t time.Time) float64 { return float64(t.UnixNano()) / 1e9 }

// LoadEntryCache returns the per-record cache entries younger than maxAge.
func LoadEntryCache(dir, name string, maxAge time.Duration) map[string]json.RawMessage {
	path := filepath.Join(dir, name)
	cacheLock.Lock()
	info, statErr := os.Stat(path)
	raw, readErr := os.ReadFile(path)
	cacheLock.Unlock()
	values := map[string]json.RawMessage{}
	if statErr != nil || readErr != nil {
		return values
	}
	cutoff := unixSeconds(time.Now().Add(-maxAge))
	for key, entry := range decodeEntryCache(raw, unixSeconds(info.ModTime())) {
		if entry.FetchedAt >= cutoff {
			values[key] = entry.Value
		}
	}
	return values
}

// MergeEntryCache atomically merges successful records with fetch times.
func MergeEntryCache(dir, name string, updates map[string]json.RawMessage) error {
	if len(updates) == 0 {
		return nil
	}
	path := filepath.Join(dir, name)
	cacheLock.Lock()
	defer cacheLock.Unlock()
	fallback := unixSeconds(time.Now())
	if info, err := os.Stat(path); err == nil {
		fallback = unixSeconds(info.ModTime())
	}
	raw, _ := os.ReadFile(path)
	entries := decodeEntryCache(raw, fallback)
	now := unixSeconds(time.Now())
	for key, value := range updates {
		if isObject(value) {
			entries[key] = cacheEntry{value, now}
		}
	}
	return atomicWriteJSON(path, map[string]any{"_schema": entryCacheSchema, "entries": entries})
}

// HTTPStatusError is a non-success HTTP response.
type HTTPStatusError struct {
	StatusCode int
	message    string
}

func (e *HTTPStatusError) Error() string { return e.message }

// StatusError reproduces httpx's raise_for_status message so recorded
// errors read the same as the Python implementation's.
func StatusError(resp *http.Response) error {
	code := resp.StatusCode
	if code >= 200 && code < 300 {
		return nil
	}
	kind := map[int]string{1: "Informational response", 3: "Redirect response", 4: "Client error", 5: "Server error"}[code/100]
	location := ""
	if code/100 == 3 {
		location = fmt.Sprintf("\nRedirect location: '%s'", resp.Header.Get("Location"))
	}
	return &HTTPStatusError{StatusCode: code, message: fmt.Sprintf("%s '%d %s' for url '%s'%s\nFor more information check: "+
		"https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/%d",
		kind, code, http.StatusText(code), resp.Request.URL, location, code)}
}

// ReadBody reads a response body bounded by MaxResponseBytes.
func ReadBody(resp *http.Response) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxResponseBytes {
		return nil, fmt.Errorf("response from %s exceeds %d bytes", resp.Request.URL, MaxResponseBytes)
	}
	return raw, nil
}

// ------------------------------------------------------------------ clients

// Endpoints are the provider URLs; tests point them at local servers.
type Endpoints struct {
	EPSS, KEV, NVD, CVERecord                      string
	MSRC, MSRCGuide, RHSA, UbuntuOSV, Debian, GHSA string
	ExploitDB                                      string
}

// DefaultEndpoints returns the public provider URLs.
func DefaultEndpoints() Endpoints {
	return Endpoints{
		EPSS:      "https://api.first.org/data/v1/epss",
		KEV:       "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
		NVD:       "https://services.nvd.nist.gov/rest/json/cves/2.0",
		CVERecord: "https://cveawg.mitre.org/api/cve",
		MSRC:      "https://api.msrc.microsoft.com/cvrf/v3.0/updates/",
		MSRCGuide: "https://msrc.microsoft.com/update-guide/vulnerability/",
		RHSA:      "https://access.redhat.com/hydra/rest/securitydata/csaf.json",
		UbuntuOSV: "https://api.osv.dev/v1/vulns/UBUNTU-",
		Debian:    "https://security-tracker.debian.org/tracker/data/json",
		GHSA:      "https://api.github.com/advisories",
		ExploitDB: "https://www.exploit-db.com/search",
	}
}

// Options control one enrichment run.
type Options struct {
	UseNVD          bool
	NVDAPIKey       string
	VendorSources   string // "" disables vendor advisories; "auto", "all" or a comma list
	GitHubToken     string
	UseVulnrichment bool
	CacheDir        string       // default DefaultCacheDir()
	HTTP            *http.Client // default a plain client
	URLs            Endpoints    // zero value = DefaultEndpoints()
}

const (
	maxRetries   = 2
	maxRetryWait = 30 * time.Second
)

// Rate-limit pauses; tests set them to zero.
var (
	retryBackoff      = time.Second
	nvdPause          = 700 * time.Millisecond // stay under NVD's unauthenticated limit
	nvdForbiddenPause = 6 * time.Second        // NVD answers 403 when rate limited
)

type client struct {
	http, noRedirect *http.Client
	dir              string
	urls             Endpoints
	o                Options
}

func (o Options) client() *client {
	base := o.HTTP
	if base == nil {
		base = &http.Client{}
	}
	noRedirect := *base
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	dir := o.CacheDir
	if dir == "" {
		dir = DefaultCacheDir()
	}
	urls := o.URLs
	if urls == (Endpoints{}) {
		urls = DefaultEndpoints()
	}
	return &client{http: base, noRedirect: &noRedirect, dir: dir, urls: urls, o: o}
}

// valueError marks invalid provider data (Python's ValueError).
type valueError string

func (e valueError) Error() string { return string(e) }

// errText renders an error like Python's f"{type(exc).__name__}: {exc}".
func errText(err error) string {
	var status *HTTPStatusError
	var syntax *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	var value valueError
	switch {
	case errors.As(err, &status):
		return "HTTPStatusError: " + err.Error()
	case errors.As(err, &value):
		return "ValueError: " + err.Error()
	case errors.As(err, &syntax), errors.As(err, &typeErr):
		return "JSONDecodeError: " + err.Error()
	case errors.Is(err, context.DeadlineExceeded):
		return "ReadTimeout: " + err.Error()
	}
	return "ConnectError: " + err.Error()
}

func retryAfter(resp *http.Response, attempt int) time.Duration {
	if seconds, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); err == nil && seconds >= 0 {
		return min(time.Duration(seconds)*time.Second, maxRetryWait)
	}
	return min(retryBackoff*time.Duration(attempt+1), maxRetryWait)
}

func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// get performs one bounded GET, retrying 429/503 a bounded number of times
// and honoring Retry-After. It returns the final response and body.
func (c *client) get(ctx context.Context, hc *http.Client, target string, headers map[string]string, timeout time.Duration) (*http.Response, []byte, error) {
	for attempt := 0; ; attempt++ {
		resp, body, err := getOnce(ctx, hc, target, headers, timeout)
		if err != nil {
			return nil, nil, err
		}
		if (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable) && attempt < maxRetries {
			if err := sleep(ctx, retryAfter(resp, attempt)); err != nil {
				return nil, nil, err
			}
			continue
		}
		return resp, body, nil
	}
}

func getOnce(ctx context.Context, hc *http.Client, target string, headers map[string]string, timeout time.Duration) (*http.Response, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "patchtriage")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := ReadBody(resp)
	return resp, body, err
}

// getJSON is get plus raise_for_status.
func (c *client) getJSON(ctx context.Context, target string, headers map[string]string, timeout time.Duration) ([]byte, error) {
	resp, body, err := c.get(ctx, c.http, target, headers, timeout)
	if err != nil {
		return nil, err
	}
	if err := StatusError(resp); err != nil {
		return nil, err
	}
	return body, nil
}

func loadCache(dir, name string, maxAge time.Duration, allowStale bool) (map[string]json.RawMessage, bool) {
	path := filepath.Join(dir, name)
	cacheLock.Lock()
	defer cacheLock.Unlock()
	info, err := os.Stat(path)
	if err != nil || (time.Since(info.ModTime()) >= maxAge && !allowStale) {
		return nil, false
	}
	raw, err := os.ReadFile(path)
	var values map[string]json.RawMessage
	if err != nil || json.Unmarshal(raw, &values) != nil || values == nil {
		return nil, false
	}
	return values, true
}

func saveCache(dir, name string, value any) error {
	cacheLock.Lock()
	defer cacheLock.Unlock()
	return atomicWriteJSON(filepath.Join(dir, name), value)
}

// ------------------------------------------------------------------ EPSS

// EPSSRow is FIRST EPSS data for one CVE; both nil means "not scored".
type EPSSRow struct {
	EPSS       *float64 `json:"epss,omitempty"`
	Percentile *float64 `json:"percentile,omitempty"`
}

func probability(v any) (float64, bool) {
	var f float64
	switch x := v.(type) {
	case float64:
		f = x
	case string:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		if err != nil {
			return 0, false
		}
		f = parsed
	default:
		return 0, false
	}
	return f, !math.IsNaN(f) && !math.IsInf(f, 0) && f >= 0 && f <= 1
}

// fetchEPSS looks up EPSS in batches; validated misses are negative-cached.
func (c *client) fetchEPSS(ctx context.Context, cves []string) (map[string]EPSSRow, error) {
	cache := map[string]EPSSRow{}
	for cve, raw := range LoadEntryCache(c.dir, "epss.json", 24*time.Hour) {
		var row EPSSRow
		if json.Unmarshal(raw, &row) == nil {
			cache[cve] = row
		}
	}
	var missing []string
	for _, cve := range cves {
		if _, ok := cache[cve]; !ok {
			missing = append(missing, cve)
		}
	}
	for start := 0; start < len(missing); start += 100 {
		batch := missing[start:min(start+100, len(missing))]
		body, err := c.getJSON(ctx, c.urls.EPSS+"?cve="+url.QueryEscape(strings.Join(batch, ",")), nil, 30*time.Second)
		if err != nil {
			return nil, err
		}
		var top map[string]json.RawMessage
		var rows []json.RawMessage
		if json.Unmarshal(body, &top) != nil || json.Unmarshal(top["data"], &rows) != nil || rows == nil {
			return nil, valueError("EPSS returned an invalid response schema")
		}
		requested := map[string]bool{}
		for _, cve := range batch {
			requested[strings.ToUpper(cve)] = true
		}
		updates := map[string]json.RawMessage{}
		for _, raw := range rows {
			var row map[string]any
			_ = json.Unmarshal(raw, &row)
			cve, ok := row["cve"].(string)
			if !ok || !requested[strings.ToUpper(cve)] {
				return nil, valueError("EPSS returned invalid probability data")
			}
			epss, okE := probability(row["epss"])
			percentile, okP := probability(row["percentile"])
			if !okE || !okP {
				return nil, valueError("EPSS returned invalid probability data")
			}
			entry := EPSSRow{EPSS: &epss, Percentile: &percentile}
			cache[strings.ToUpper(cve)] = entry
			updates[strings.ToUpper(cve)], _ = json.Marshal(entry)
		}
		for _, cve := range batch { // negative-cache CVEs EPSS doesn't know
			if _, ok := updates[cve]; !ok {
				cache[cve] = EPSSRow{}
				updates[cve] = json.RawMessage(`{}`)
			}
		}
		_ = MergeEntryCache(c.dir, "epss.json", updates)
	}
	return cache, nil
}

// ------------------------------------------------------------------ CISA KEV

// KEVEntry is one CISA KEV catalog row.
type KEVEntry struct {
	CVEID                      string  `json:"cveID"`
	KnownRansomwareCampaignUse string  `json:"knownRansomwareCampaignUse"`
	DueDate                    *string `json:"dueDate"`
	DateAdded                  *string `json:"dateAdded"`
}

// kevResult carries freshness: a stale catalog substantiates positive
// listings only, never non-membership.
type kevResult struct {
	entries      map[string]KEVEntry
	stale        bool
	refreshError string
}

func decodeKEV(values map[string]json.RawMessage) (map[string]KEVEntry, bool) {
	if len(values) == 0 {
		return nil, false
	}
	entries := map[string]KEVEntry{}
	for cve, raw := range values {
		var entry KEVEntry
		if !strings.HasPrefix(strings.ToUpper(cve), "CVE-") || json.Unmarshal(raw, &entry) != nil ||
			!strings.EqualFold(entry.CVEID, cve) {
			return nil, false
		}
		entries[cve] = entry
	}
	return entries, true
}

func (c *client) fetchKEV(ctx context.Context) (kevResult, error) {
	if cached, ok := loadCache(c.dir, "kev.json", 24*time.Hour, false); ok {
		if entries, valid := decodeKEV(cached); valid {
			return kevResult{entries: entries}, nil
		}
	}
	fetched, err := c.downloadKEV(ctx)
	if err != nil {
		if stale, ok := loadCache(c.dir, "kev.json", 24*time.Hour, true); ok {
			if entries, valid := decodeKEV(stale); valid {
				return kevResult{entries: entries, stale: true, refreshError: errText(err)}, nil
			}
		}
		return kevResult{}, err
	}
	entries, _ := decodeKEV(fetched)
	_ = saveCache(c.dir, "kev.json", fetched)
	return kevResult{entries: entries}, nil
}

func (c *client) downloadKEV(ctx context.Context) (map[string]json.RawMessage, error) {
	body, err := c.getJSON(ctx, c.urls.KEV, nil, 60*time.Second)
	if err != nil {
		return nil, err
	}
	var payload struct {
		Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	if len(payload.Vulnerabilities) == 0 {
		return nil, valueError("CISA KEV returned an invalid or empty catalog")
	}
	fetched := map[string]json.RawMessage{}
	for _, raw := range payload.Vulnerabilities {
		var row struct {
			CVEID any `json:"cveID"`
		}
		if !isObject(raw) || json.Unmarshal(raw, &row) != nil {
			return nil, valueError("CISA KEV returned an invalid catalog row")
		}
		cve, ok := row.CVEID.(string)
		if !ok || !strings.HasPrefix(strings.ToUpper(cve), "CVE-") {
			return nil, valueError("CISA KEV catalog row is missing cveID")
		}
		fetched[strings.ToUpper(cve)] = raw
	}
	if _, valid := decodeKEV(fetched); !valid {
		return nil, valueError("CISA KEV catalog failed schema validation")
	}
	return fetched, nil
}

// ------------------------------------------------------------------ NVD

// ReferenceRecord is one NVD reference with its tags.
type ReferenceRecord struct {
	URL  string   `json:"url"`
	Tags []string `json:"tags"`
}

// NVDEntry is the cached NVD summary for one CVE.
type NVDEntry struct {
	Score            *float64          `json:"score,omitempty"`
	Vector           string            `json:"vector,omitempty"`
	Version          string            `json:"version,omitempty"`
	CWEs             []string          `json:"cwes"`
	ReferenceRecords []ReferenceRecord `json:"reference_records,omitempty"`
	References       []string          `json:"references"`
}

// found mirrors Python's truthiness of the entry dict.
func (n NVDEntry) found() bool {
	return n.Score != nil || n.Vector != "" || n.Version != "" || n.CWEs != nil || n.ReferenceRecords != nil || n.References != nil
}

type nvdRecord struct {
	ID         string                       `json:"id"`
	Metrics    map[string][]json.RawMessage `json:"metrics"`
	Weaknesses []struct {
		Description []struct {
			Value string `json:"value"`
		} `json:"description"`
	} `json:"weaknesses"`
	References []struct {
		URL  *string `json:"url"`
		Tags []any   `json:"tags"`
	} `json:"references"`
}

func (c *client) fetchNVD(ctx context.Context, cve string) (NVDEntry, error) {
	if raw, ok := LoadEntryCache(c.dir, "nvd.json", 7*24*time.Hour)[cve]; ok {
		var cached NVDEntry
		if json.Unmarshal(raw, &cached) == nil && cached.found() {
			return cached, nil
		}
	}
	headers := map[string]string{}
	if c.o.NVDAPIKey != "" {
		headers["apiKey"] = c.o.NVDAPIKey
	}
	target := c.urls.NVD + "?cveId=" + url.QueryEscape(cve)
	resp, body, err := c.get(ctx, c.http, target, headers, 30*time.Second)
	if err == nil && resp.StatusCode == http.StatusForbidden { // rate limited: back off once
		if err = sleep(ctx, nvdForbiddenPause); err == nil {
			resp, body, err = c.get(ctx, c.http, target, headers, 30*time.Second)
		}
	}
	if err != nil {
		return NVDEntry{}, err
	}
	if err := StatusError(resp); err != nil {
		return NVDEntry{}, err
	}
	var payload struct {
		Vulnerabilities *[]json.RawMessage `json:"vulnerabilities"`
	}
	if json.Unmarshal(body, &payload) != nil || payload.Vulnerabilities == nil {
		return NVDEntry{}, valueError("NVD returned an invalid response schema")
	}
	if len(*payload.Vulnerabilities) == 0 {
		return NVDEntry{}, nil // never cache an empty record: publication can lag
	}
	var item struct {
		CVE *nvdRecord `json:"cve"`
	}
	if json.Unmarshal((*payload.Vulnerabilities)[0], &item) != nil || item.CVE == nil {
		return NVDEntry{}, valueError("NVD returned an invalid vulnerability record")
	}
	record := item.CVE
	if record.ID != "" && !strings.EqualFold(record.ID, cve) {
		return NVDEntry{}, valueError("NVD returned a record for a different CVE")
	}
	entry := NVDEntry{CWEs: []string{}, References: []string{}, ReferenceRecords: []ReferenceRecord{}}
	for _, version := range []string{"cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"} {
		rows := record.Metrics[version]
		if len(rows) == 0 {
			continue
		}
		var metric struct {
			CVSSData *struct {
				BaseScore    *float64 `json:"baseScore"`
				VectorString string   `json:"vectorString"`
				Version      string   `json:"version"`
			} `json:"cvssData"`
		}
		if json.Unmarshal(rows[0], &metric) != nil || metric.CVSSData == nil {
			return NVDEntry{}, valueError("NVD returned invalid CVSS metric data")
		}
		entry.Score, entry.Vector, entry.Version = metric.CVSSData.BaseScore, metric.CVSSData.VectorString, metric.CVSSData.Version
		break
	}
	for _, weakness := range record.Weaknesses {
		for _, d := range weakness.Description {
			if strings.HasPrefix(d.Value, "CWE-") {
				entry.CWEs = append(entry.CWEs, d.Value)
			}
		}
	}
	for _, ref := range record.References {
		if ref.URL == nil {
			continue
		}
		tags := []string{}
		for _, tag := range ref.Tags {
			tags = append(tags, fmt.Sprint(tag))
		}
		entry.ReferenceRecords = append(entry.ReferenceRecords, ReferenceRecord{URL: *ref.URL, Tags: tags})
		entry.References = append(entry.References, *ref.URL)
	}
	raw, _ := json.Marshal(entry)
	_ = MergeEntryCache(c.dir, "nvd.json", map[string]json.RawMessage{cve: raw})
	if c.o.NVDAPIKey == "" {
		_ = sleep(ctx, nvdPause)
	}
	return entry, nil
}

var exploitReferenceDomains = []string{"exploit-db.com", "packetstormsecurity.com"}

func isKnownExploitReference(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := strings.TrimRight(strings.ToLower(parsed.Hostname()), ".")
	for _, domain := range exploitReferenceDomains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return host == "github.com" && strings.HasPrefix(strings.ToLower(parsed.Path), "/rapid7/")
}

func firstUnique(values []string, n int) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range values {
		if !seen[v] && len(out) < n {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// exploitReferenceURLs prefers NVD's structured Exploit tag, then narrow
// trusted exploit hosts. A generic "poc" substring is not evidence.
func exploitReferenceURLs(n NVDEntry) []string {
	var tagged, urls []string
	for _, record := range n.ReferenceRecords {
		if record.URL == "" {
			continue
		}
		urls = append(urls, record.URL)
		for _, tag := range record.Tags {
			if strings.EqualFold(strings.TrimSpace(tag), "exploit") {
				tagged = append(tagged, record.URL)
				break
			}
		}
	}
	if len(tagged) > 0 {
		return firstUnique(tagged, 5)
	}
	if len(urls) == 0 {
		for _, u := range n.References {
			if u != "" {
				urls = append(urls, u)
			}
		}
	}
	var known []string
	for _, u := range urls {
		if isKnownExploitReference(u) {
			known = append(known, u)
		}
	}
	return firstUnique(known, 5)
}

// ------------------------------------------------------- CISA Vulnrichment

// VulnrichmentEntry records a completed lookup: assessed decision points or
// an explicit "not assessed" with its reason.
type VulnrichmentEntry struct {
	Assessed        bool    `json:"assessed"`
	Reason          string  `json:"reason,omitempty"`
	Exploitation    *string `json:"Exploitation,omitempty"`
	Automatable     *string `json:"Automatable,omitempty"`
	TechnicalImpact *string `json:"Technical Impact,omitempty"`
	Role            string  `json:"role,omitempty"`
	Version         string  `json:"version,omitempty"`
	Timestamp       string  `json:"timestamp,omitempty"`
}

func (v VulnrichmentEntry) hasPoints() bool {
	return v.Exploitation != nil || v.Automatable != nil || v.TechnicalImpact != nil
}

var vulnrichmentPoints = map[string][]string{
	"Exploitation": {"none", "poc", "active"}, "Automatable": {"yes", "no"}, "Technical Impact": {"partial", "total"},
}

func objectOf(raw json.RawMessage) map[string]json.RawMessage {
	var f map[string]json.RawMessage
	_ = json.Unmarshal(raw, &f)
	return f
}

func listOf(raw json.RawMessage) []json.RawMessage {
	var l []json.RawMessage
	_ = json.Unmarshal(raw, &l)
	return l
}

func textOf(raw json.RawMessage) (string, bool) {
	var s string
	return s, raw != nil && json.Unmarshal(raw, &s) == nil
}

// ParseVulnrichmentSSVC extracts CISA's own SSVC decision points from a CVE
// record. Other publishers' blocks and values outside the published
// vocabulary are ignored; no points means "not assessed by CISA".
func ParseVulnrichmentSSVC(record []byte) VulnrichmentEntry {
	containers := objectOf(objectOf(record)["containers"])
	for _, container := range listOf(containers["adp"]) {
		c := objectOf(container)
		short, ok := textOf(objectOf(c["providerMetadata"])["shortName"])
		if !ok || strings.ToLower(strings.TrimSpace(short)) != "cisa-adp" {
			continue
		}
		for _, metric := range listOf(c["metrics"]) {
			other := objectOf(objectOf(metric)["other"])
			if kind, _ := textOf(other["type"]); kind != "ssvc" {
				continue
			}
			content := objectOf(other["content"])
			if content == nil {
				continue
			}
			var entry VulnrichmentEntry
			for _, option := range listOf(content["options"]) {
				o := objectOf(option)
				for name, allowed := range vulnrichmentPoints {
					value, ok := textOf(o[name])
					value = strings.ToLower(strings.TrimSpace(value))
					if !ok || !contains(allowed, value) {
						continue
					}
					v := value
					switch name {
					case "Exploitation":
						entry.Exploitation = &v
					case "Automatable":
						entry.Automatable = &v
					default:
						entry.TechnicalImpact = &v
					}
				}
			}
			if !entry.hasPoints() {
				continue
			}
			entry.Role, _ = textOf(content["role"])
			entry.Version, _ = textOf(content["version"])
			entry.Timestamp, _ = textOf(content["timestamp"])
			return entry
		}
	}
	return VulnrichmentEntry{}
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

// fetchVulnrichment fetches one CVE record's CISA SSVC points. The cache
// records that a lookup happened, including "not assessed".
func (c *client) fetchVulnrichment(ctx context.Context, cve string) (VulnrichmentEntry, error) {
	if raw, ok := LoadEntryCache(c.dir, "vulnrichment.json", 7*24*time.Hour)[cve]; ok && len(objectOf(raw)) > 0 {
		var cached VulnrichmentEntry
		if json.Unmarshal(raw, &cached) == nil {
			return cached, nil
		}
	}
	resp, body, err := c.get(ctx, c.noRedirect, c.urls.CVERecord+"/"+cve, map[string]string{"Accept": "application/json"}, 30*time.Second)
	if err != nil {
		return VulnrichmentEntry{}, err
	}
	var entry VulnrichmentEntry
	if resp.StatusCode == http.StatusNotFound {
		entry = VulnrichmentEntry{Reason: "no published CVE record"}
	} else {
		if err := StatusError(resp); err != nil {
			return VulnrichmentEntry{}, err
		}
		if !json.Valid(body) {
			return VulnrichmentEntry{}, valueError("CVE record is not valid JSON")
		}
		entry = ParseVulnrichmentSSVC(body)
		entry.Assessed = entry.hasPoints()
		if !entry.Assessed {
			entry.Reason = "CVE record carries no CISA SSVC assessment"
		}
	}
	raw, _ := json.Marshal(entry)
	_ = MergeEntryCache(c.dir, "vulnrichment.json", map[string]json.RawMessage{cve: raw})
	return entry, nil
}

// ------------------------------------------------------------------ apply

func applyVulnrichment(e *model.Enrichment, v VulnrichmentEntry) {
	e.SSVCExploitation, e.SSVCAutomatable, e.SSVCTechnicalImpact = v.Exploitation, v.Automatable, v.TechnicalImpact
	e.SSVCRole, e.SSVCVersion, e.SSVCTimestamp = v.Role, v.Version, v.Timestamp
}

func appendOnce(values []string, value string) []string {
	if contains(values, value) {
		return values
	}
	return append(values, value)
}

func applyKEV(e *model.Enrichment, k KEVEntry) {
	e.InCISAKEV = true
	e.KEVRansomware = strings.ToLower(k.KnownRansomwareCampaignUse) == "known"
	e.KEVDueDate, e.KEVDateAdded = k.DueDate, k.DateAdded
}

func applyNVD(e *model.Enrichment, n NVDEntry) {
	e.NVDCVSSScore, e.NVDCVSSVector, e.NVDCVSSVersion = n.Score, n.Vector, n.Version
	e.CWEIDs = n.CWEs
	if e.CWEIDs == nil {
		e.CWEIDs = []string{}
	}
	e.ExploitRefs = exploitReferenceURLs(n)
}

func prepare(f *model.Finding, now time.Time) *model.Enrichment {
	e := &f.Enrichment
	e.EnrichedAt = &now
	if e.RetrievalStatus == nil {
		e.RetrievalStatus = map[string]string{}
	}
	if !strings.HasPrefix(f.VulnID, "CVE-") {
		for _, source := range []string{"epss", "kev", "nvd", "vulnrichment"} {
			e.RetrievalStatus[source] = "not_applicable"
		}
		return nil
	}
	return e
}

func foundStatus(ok bool) string {
	if ok {
		return "found"
	}
	return "not_found"
}

func uniqueSorted(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range values {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// Enrich attaches EPSS, KEV, NVD, Vulnrichment and optional vendor records
// in place. Each source fails independently and visibly.
func Enrich(ctx context.Context, findings []*model.Finding, o Options) error {
	c := o.client()
	var cves []string
	for _, f := range findings {
		if strings.HasPrefix(f.VulnID, "CVE-") {
			cves = append(cves, f.VulnID)
		}
	}
	now := time.Now().UTC()
	epss, epssErr := c.fetchEPSS(ctx, uniqueSorted(cves))
	kev, kevErr := c.fetchKEV(ctx)
	for _, f := range findings {
		e := prepare(f, now)
		if e == nil {
			continue
		}
		if epssErr != nil {
			e.RetrievalStatus["epss"] = "failed"
			e.RetrievalErrors = append(e.RetrievalErrors, "EPSS: "+errText(epssErr))
		} else {
			row := epss[f.VulnID]
			e.EPSSScore, e.EPSSPercentile = row.EPSS, row.Percentile
			e.RetrievalStatus["epss"] = foundStatus(row.EPSS != nil || row.Percentile != nil)
			e.Sources = append(e.Sources, "epss")
		}
		if kevErr != nil {
			e.RetrievalStatus["kev"] = "failed"
			e.RetrievalErrors = append(e.RetrievalErrors, "CISA KEV: "+errText(kevErr))
		} else {
			entry, listed := kev.entries[f.VulnID]
			if listed {
				applyKEV(e, entry)
			}
			switch {
			case kev.stale && listed:
				e.RetrievalStatus["kev"] = "listed_stale"
			case kev.stale:
				e.RetrievalStatus["kev"] = "unknown_stale"
			case listed:
				e.RetrievalStatus["kev"] = "listed"
			default:
				e.RetrievalStatus["kev"] = "not_listed"
			}
			if kev.stale {
				warning := "CISA KEV: live refresh failed; a stale catalog was used for positive matches only"
				if kev.refreshError != "" {
					warning += " (" + kev.refreshError + ")"
				}
				e.RetrievalErrors = append(e.RetrievalErrors, warning)
				e.Sources = append(e.Sources, "kev:stale")
			} else {
				e.Sources = append(e.Sources, "kev")
			}
		}
		if o.UseNVD {
			n, err := c.fetchNVD(ctx, f.VulnID)
			if err != nil {
				e.RetrievalStatus["nvd"] = "failed"
				e.RetrievalErrors = append(e.RetrievalErrors, "NVD: "+errText(err))
			} else {
				applyNVD(e, n)
				e.RetrievalStatus["nvd"] = foundStatus(n.found())
				if n.found() {
					e.ExploitSourcesChecked = appendOnce(e.ExploitSourcesChecked, "nvd")
				}
				e.Sources = append(e.Sources, "nvd")
			}
		} else {
			e.RetrievalStatus["nvd"] = "disabled"
		}
		if o.UseVulnrichment {
			v, err := c.fetchVulnrichment(ctx, f.VulnID)
			if err != nil {
				e.RetrievalStatus["vulnrichment"] = "failed"
				e.RetrievalErrors = append(e.RetrievalErrors, "CISA Vulnrichment: "+errText(err))
			} else {
				if v.Assessed && v.hasPoints() {
					applyVulnrichment(e, v)
					e.RetrievalStatus["vulnrichment"] = "found"
					// CISA's published Exploitation verdict is a completed
					// exploit-evidence search by an authoritative source.
					e.ExploitSourcesChecked = appendOnce(e.ExploitSourcesChecked, "cisa-vulnrichment")
				} else {
					e.RetrievalStatus["vulnrichment"] = "not_found"
				}
				e.Sources = append(e.Sources, "vulnrichment")
			}
		} else {
			e.RetrievalStatus["vulnrichment"] = "disabled"
		}
	}
	return nil
}

// ------------------------------------------------------------------ snapshot

// Snapshot is bundled deterministic evidence for the offline demo.
type Snapshot struct {
	EPSS         map[string]EPSSRow
	KEV          map[string]KEVEntry
	NVD          map[string]NVDEntry
	Vulnrichment map[string]VulnrichmentEntry
}

// DemoSnapshot loads the bundled demo evidence.
func DemoSnapshot() (Snapshot, error) {
	var s Snapshot
	for name, target := range map[string]any{
		"demo_epss.json": &s.EPSS, "demo_kev.json": &s.KEV, "demo_nvd.json": &s.NVD, "demo_vulnrichment.json": &s.Vulnrichment,
	} {
		raw, err := data.ReadFile(name)
		if err != nil {
			return Snapshot{}, err
		}
		if err := json.Unmarshal(raw, target); err != nil {
			return Snapshot{}, fmt.Errorf("%s: %w", name, err)
		}
	}
	return s, nil
}

// SeedDemoCache writes the demo evidence into an isolated cache directory,
// exactly like the Python CLI demo, so the regular enrichment runs offline
// without touching a real cache.
func SeedDemoCache(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for _, name := range []string{"epss", "kev", "nvd", "vulnrichment"} {
		raw, err := data.ReadFile("demo_" + name + ".json")
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, name+".json"), raw, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// EnrichFromSnapshot attaches bundled evidence without network or cache.
func EnrichFromSnapshot(findings []*model.Finding, s Snapshot) {
	now := time.Now().UTC()
	for _, f := range findings {
		e := prepare(f, now)
		if e == nil {
			continue
		}
		row := s.EPSS[f.VulnID]
		e.EPSSScore, e.EPSSPercentile = row.EPSS, row.Percentile
		e.RetrievalStatus["epss"] = foundStatus(row.EPSS != nil || row.Percentile != nil)
		e.Sources = append(e.Sources, "epss:snapshot")
		entry, listed := s.KEV[f.VulnID]
		e.RetrievalStatus["kev"] = "not_listed"
		if listed {
			applyKEV(e, entry)
			e.RetrievalStatus["kev"] = "listed"
		}
		e.Sources = append(e.Sources, "kev:snapshot")
		n := s.NVD[f.VulnID]
		applyNVD(e, n)
		e.RetrievalStatus["nvd"] = foundStatus(n.found())
		if n.found() {
			e.ExploitSourcesChecked = appendOnce(e.ExploitSourcesChecked, "nvd:snapshot")
		}
		e.Sources = append(e.Sources, "nvd:snapshot")
		if v := s.Vulnrichment[f.VulnID]; v.Assessed && v.hasPoints() {
			applyVulnrichment(e, v)
			e.RetrievalStatus["vulnrichment"] = "found"
			e.ExploitSourcesChecked = appendOnce(e.ExploitSourcesChecked, "cisa-vulnrichment:snapshot")
		} else {
			e.RetrievalStatus["vulnrichment"] = "not_found"
		}
		e.Sources = append(e.Sources, "vulnrichment:snapshot")
	}
}
