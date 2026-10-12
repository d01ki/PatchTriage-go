package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/d01ki/PatchTriage-go/internal/decision"
	"github.com/d01ki/PatchTriage-go/internal/model"
)

func init() {
	retryBackoff = 0
	nvdPause, nvdForbiddenPause = 0, 0
}

func cveRecord(provider string, options string) string {
	return `{"containers": {"adp": [{"providerMetadata": {"shortName": "` + provider + `"},
		"metrics": [{"other": {"type": "ssvc", "content": {"id": "CVE-2024-3400", "role": "CISA Coordinator",
		"options": ` + options + `, "version": "2.0.3", "timestamp": "2024-04-17T04:00:13.543064Z"}}}]}]}}`
}

const fullOptions = `[{"Exploitation": "active"}, {"Automatable": "yes"}, {"Technical Impact": "total"}]`

func TestParseVulnrichmentSSVC(t *testing.T) {
	parsed := ParseVulnrichmentSSVC([]byte(cveRecord("CISA-ADP", fullOptions)))
	if *parsed.Exploitation != "active" || *parsed.Automatable != "yes" || *parsed.TechnicalImpact != "total" ||
		parsed.Role != "CISA Coordinator" || parsed.Version != "2.0.3" || !parsed.hasPoints() {
		t.Errorf("parsed = %+v", parsed)
	}
	if ParseVulnrichmentSSVC([]byte(cveRecord("acme-adp", fullOptions))).hasPoints() {
		t.Error("another provider's SSVC block must be ignored")
	}
	vocab := ParseVulnrichmentSSVC([]byte(cveRecord("CISA-ADP",
		`[{"Exploitation": "extremely-bad"}, {"Automatable": "maybe"}, {"Technical Impact": "total"}]`)))
	if vocab.Exploitation != nil || vocab.Automatable != nil || *vocab.TechnicalImpact != "total" {
		t.Errorf("vocabulary filter = %+v", vocab)
	}
	for _, malformed := range []string{`{}`, `{"containers": null}`, `{"containers": {"adp": [null]}}`,
		`{"containers": {"adp": [{"providerMetadata": {"shortName": "CISA-ADP"}}]}}`, `"not-a-record"`, `null`} {
		if ParseVulnrichmentSSVC([]byte(malformed)).hasPoints() {
			t.Errorf("%s parsed to points", malformed)
		}
	}
}

// server is a scripted provider: each path serves a queue of responses and
// then repeats the last one.
type server struct {
	t     *testing.T
	mu    sync.Mutex
	calls map[string]int
	plans map[string][]func(http.ResponseWriter)
	*httptest.Server
}

func newServer(t *testing.T) *server {
	s := &server{t: t, calls: map[string]int{}, plans: map[string][]func(http.ResponseWriter){}}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		plan := s.plans[r.URL.Path]
		n := s.calls[r.URL.Path]
		s.calls[r.URL.Path]++
		s.mu.Unlock()
		if len(plan) == 0 {
			t.Errorf("unexpected request %s", r.URL)
			http.Error(w, "unexpected", http.StatusTeapot)
			return
		}
		plan[min(n, len(plan)-1)](w)
	}))
	t.Cleanup(s.Close)
	return s
}

func reply(status int, body string, headers ...string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		for i := 0; i+1 < len(headers); i += 2 {
			w.Header().Set(headers[i], headers[i+1])
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

func (s *server) on(path string, replies ...func(http.ResponseWriter)) { s.plans[path] = replies }

func (s *server) count(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[path]
}

func (s *server) options(t *testing.T) Options {
	return Options{UseNVD: true, UseVulnrichment: true, CacheDir: t.TempDir(), HTTP: s.Client(), URLs: Endpoints{
		EPSS: s.URL + "/epss", KEV: s.URL + "/kev", NVD: s.URL + "/nvd", CVERecord: s.URL + "/cve"}}
}

func newClient(o Options) *client { return o.client() }

func TestFetchVulnrichmentCachesAndNotFound(t *testing.T) {
	s := newServer(t)
	s.on("/cve/CVE-2024-3400", reply(200, cveRecord("CISA-ADP", fullOptions)))
	s.on("/cve/CVE-2020-8203", reply(200, `{"containers": {"adp": []}}`))
	s.on("/cve/CVE-9999-99999", reply(404, ""))
	s.on("/cve/CVE-2024-0500", reply(500, ""))
	c := newClient(s.options(t))
	ctx := context.Background()
	first, err := c.fetchVulnrichment(ctx, "CVE-2024-3400")
	second, _ := c.fetchVulnrichment(ctx, "CVE-2024-3400")
	if err != nil || !first.Assessed || *first.Exploitation != "active" || !reflect.DeepEqual(first, second) ||
		s.count("/cve/CVE-2024-3400") != 1 {
		t.Errorf("positive assessment not cached: %+v %v", first, err)
	}
	unassessed, _ := c.fetchVulnrichment(ctx, "CVE-2020-8203")
	_, _ = c.fetchVulnrichment(ctx, "CVE-2020-8203")
	if unassessed.Assessed || unassessed.Reason == "" || s.count("/cve/CVE-2020-8203") != 1 {
		t.Errorf("unassessed = %+v", unassessed)
	}
	if missing, err := c.fetchVulnrichment(ctx, "CVE-9999-99999"); err != nil || missing.Assessed {
		t.Errorf("404 must be 'no record', not an error: %+v %v", missing, err)
	}
	if _, err := c.fetchVulnrichment(ctx, "CVE-2024-0500"); err == nil {
		t.Error("a server error must not be faked into an assessment")
	}
}

func TestFetchEPSSValidation(t *testing.T) {
	s := newServer(t)
	s.on("/epss", reply(200, `{"unexpected": []}`))
	o := s.options(t)
	if _, err := newClient(o).fetchEPSS(context.Background(), []string{"CVE-2024-0001"}); err == nil ||
		!strings.Contains(err.Error(), "invalid response schema") {
		t.Errorf("err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(o.CacheDir, "epss.json")); err == nil {
		t.Error("an invalid response must not create negative cache entries")
	}
	s.on("/epss", reply(200, `{"data": [{"cve": "CVE-2024-0001", "epss": "1.5", "percentile": "0.2"}]}`))
	if _, err := newClient(o).fetchEPSS(context.Background(), []string{"CVE-2024-0001"}); err == nil {
		t.Error("an out-of-range probability must be rejected")
	}
	s.on("/epss", reply(200, `{"data": [{"cve": "CVE-2024-0001", "epss": "0.5", "percentile": 0.9}]}`))
	rows, err := newClient(o).fetchEPSS(context.Background(), []string{"CVE-2024-0001", "CVE-2024-0002"})
	if err != nil || *rows["CVE-2024-0001"].EPSS != 0.5 || rows["CVE-2024-0002"].EPSS != nil {
		t.Errorf("rows = %v %v", rows, err)
	}
	if _, err := newClient(o).fetchEPSS(context.Background(), []string{"CVE-2024-0002"}); err != nil || s.count("/epss") != 3 {
		t.Error("a validated miss is negative-cached")
	}
}

func TestFetchKEVStaleFallback(t *testing.T) {
	s := newServer(t)
	s.on("/kev", reply(200, `{"vulnerabilities": []}`))
	o := s.options(t)
	if _, err := newClient(o).fetchKEV(context.Background()); err == nil || !strings.Contains(err.Error(), "invalid or empty catalog") {
		t.Errorf("err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(o.CacheDir, "kev.json")); err == nil {
		t.Error("an invalid catalog must not be cached")
	}
	known := `{"CVE-2024-0001": {"cveID": "CVE-2024-0001"}}`
	path := filepath.Join(o.CacheDir, "kev.json")
	_ = os.WriteFile(path, []byte(known), 0o600)
	old := time.Now().Add(-48 * time.Hour)
	_ = os.Chtimes(path, old, old)
	result, err := newClient(o).fetchKEV(context.Background())
	if err != nil || !result.stale || !strings.Contains(result.refreshError, "invalid or empty catalog") ||
		result.entries["CVE-2024-0001"].CVEID != "CVE-2024-0001" {
		t.Errorf("stale fallback = %+v %v", result, err)
	}
	if raw, _ := os.ReadFile(path); string(raw) != known {
		t.Error("the last known good catalog must not be overwritten")
	}
}

func TestFetchNVDReferencesAndNoNegativeCache(t *testing.T) {
	s := newServer(t)
	s.on("/nvd", reply(500, ""))
	o := s.options(t)
	c := newClient(o)
	if _, err := c.fetchNVD(context.Background(), "CVE-2024-0001"); err == nil {
		t.Error("expected a status error")
	}
	s.on("/nvd", reply(200, `{"vulnerabilities": []}`))
	if entry, err := c.fetchNVD(context.Background(), "CVE-2024-0001"); err != nil || entry.found() {
		t.Errorf("empty = %+v %v", entry, err)
	}
	if _, err := os.Stat(filepath.Join(o.CacheDir, "nvd.json")); err == nil {
		t.Error("failures and empty records are never cached")
	}
	s.on("/nvd", reply(200, `{"vulnerabilities": [{"cve": {"id": "CVE-2024-0001", "metrics": {
		"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N", "version": "3.1"}}]},
		"weaknesses": [{"description": [{"value": "CWE-79"}, {"value": "NVD-CWE-noinfo"}]}],
		"references": [
			{"url": "https://example.test/advisory/epoch-poc-policy", "tags": ["Vendor Advisory"]},
			{"url": "https://research.example.test/reproducer", "tags": ["Exploit", "Third Party Advisory"]},
			{"url": "https://www.exploit-db.com/exploits/123", "tags": []}]}}]}`))
	entry, err := c.fetchNVD(context.Background(), "CVE-2024-0001")
	if err != nil || *entry.Score != 9.8 || entry.Vector != "CVSS:3.1/AV:N" || strings.Join(entry.CWEs, ",") != "CWE-79" ||
		strings.Join(entry.ReferenceRecords[1].Tags, ",") != "Exploit,Third Party Advisory" {
		t.Errorf("entry = %+v %v", entry, err)
	}
	if refs := exploitReferenceURLs(entry); strings.Join(refs, ",") != "https://research.example.test/reproducer" {
		t.Errorf("exploit tag must win: %v", refs)
	}
	if cached, _ := c.fetchNVD(context.Background(), "CVE-2024-0001"); !reflect.DeepEqual(cached, entry) || s.count("/nvd") != 3 {
		t.Error("a found record is served from the cache")
	}
	s.on("/nvd", reply(200, `{"vulnerabilities": [{"cve": {"id": "CVE-2024-9999"}}]}`))
	if _, err := c.fetchNVD(context.Background(), "CVE-2024-0002"); err == nil {
		t.Error("a record for a different CVE must be rejected")
	}
}

func TestExploitReferenceURLs(t *testing.T) {
	if refs := exploitReferenceURLs(NVDEntry{References: []string{"https://example.test/advisory/epoch-poc-policy"}}); len(refs) != 0 {
		t.Errorf("poc substring alone is not exploit evidence: %v", refs)
	}
	refs := exploitReferenceURLs(NVDEntry{References: []string{
		"https://packetstormsecurity.com/files/1", "https://github.com/rapid7/metasploit-framework/pull/1",
		"https://github.com/other/repo", "https://www.exploit-db.com./exploits/9", "https://evil-exploit-db.com/x"}})
	if strings.Join(refs, ",") != "https://packetstormsecurity.com/files/1,https://github.com/rapid7/metasploit-framework/pull/1,https://www.exploit-db.com./exploits/9" {
		t.Errorf("refs = %v", refs)
	}
}

func TestEntryCacheConcurrentMergeAndPerRecordTTL(t *testing.T) {
	dir := t.TempDir()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = MergeEntryCache(dir, "nvd.json", map[string]json.RawMessage{fmt.Sprintf("CVE-2024-%04d", i): json.RawMessage(fmt.Sprintf(`{"score": %d}`, i))})
		}(i)
	}
	wg.Wait()
	if got := len(LoadEntryCache(dir, "nvd.json", time.Hour)); got != 20 {
		t.Errorf("merged %d entries, want 20", got)
	}
	if temps, _ := filepath.Glob(filepath.Join(dir, "*.tmp")); len(temps) != 0 {
		t.Errorf("temp files left behind: %v", temps)
	}
	now := float64(time.Now().Unix())
	_ = atomicWriteJSON(filepath.Join(dir, "ttl.json"), map[string]any{"_schema": entryCacheSchema, "entries": map[string]any{
		"old": map[string]any{"value": map[string]int{"score": 1}, "fetched_at": now - 10*3600},
		"new": map[string]any{"value": map[string]int{"score": 2}, "fetched_at": now}}})
	if got := LoadEntryCache(dir, "ttl.json", time.Hour); len(got) != 1 || got["new"] == nil {
		t.Errorf("per-record TTL = %v", got)
	}
}

func cveFinding(id string) *model.Finding {
	return &model.Finding{Key: id, VulnID: id, Package: model.Package{Name: "pkg"}, Asset: model.NewAsset("asset")}
}

func TestEnrichKEVFailureIsNotAbsence(t *testing.T) {
	s := newServer(t)
	s.on("/epss", reply(200, `{"data": []}`))
	s.on("/kev", reply(500, ""))
	f := cveFinding("CVE-2024-0001")
	o := s.options(t)
	o.UseNVD, o.UseVulnrichment = false, false
	if err := Enrich(context.Background(), []*model.Finding{f}, o); err != nil {
		t.Fatal(err)
	}
	e := f.Enrichment
	if e.InCISAKEV || e.RetrievalStatus["kev"] != "failed" || !strings.HasPrefix(e.RetrievalErrors[0], "CISA KEV: HTTPStatusError: Server error '500") {
		t.Errorf("enrichment = %+v", e)
	}
	f.Triage = decision.Triage(f)
	if decision.EvaluateBOD(f).Inputs.InKEV.Resolved {
		t.Error("a failed KEV lookup must leave BOD In KEV unresolved")
	}
}

func TestEnrichSourceOutagesAreIsolated(t *testing.T) {
	s := newServer(t)
	s.on("/epss", reply(200, `not json`))
	s.on("/kev", reply(200, `{"vulnerabilities": [{"cveID": "CVE-2024-0001", "knownRansomwareCampaignUse": "Unknown"}]}`))
	s.on("/nvd", reply(200, `{"vulnerabilities": "bad"}`))
	s.on("/cve/CVE-2024-0001", reply(503, ""))
	f := cveFinding("CVE-2024-0001")
	o := s.options(t)
	if err := Enrich(context.Background(), []*model.Finding{f}, o); err != nil {
		t.Fatal(err)
	}
	e := f.Enrichment
	want := map[string]string{"epss": "failed", "kev": "listed", "nvd": "failed", "vulnrichment": "failed"}
	if !reflect.DeepEqual(e.RetrievalStatus, want) || !e.InCISAKEV || e.SSVCExploitation != nil || e.SSVCAutomatable != nil {
		t.Errorf("enrichment = %+v", e)
	}
	prefixes := []string{"EPSS:", "NVD:", "CISA Vulnrichment:"}
	for _, prefix := range prefixes {
		found := false
		for _, msg := range e.RetrievalErrors {
			found = found || strings.HasPrefix(msg, prefix)
		}
		if !found {
			t.Errorf("no %s error in %v", prefix, e.RetrievalErrors)
		}
	}
}

func TestEnrichRetriesOn429ThenRecords(t *testing.T) {
	s := newServer(t)
	s.on("/epss", reply(429, "", "Retry-After", "0"), reply(200, `{"data": [{"cve": "CVE-2024-0001", "epss": 0.3, "percentile": 0.5}]}`))
	s.on("/kev", reply(429, "", "Retry-After", "0"))
	f := cveFinding("CVE-2024-0001")
	o := s.options(t)
	o.UseNVD, o.UseVulnrichment = false, false
	if err := Enrich(context.Background(), []*model.Finding{f}, o); err != nil {
		t.Fatal(err)
	}
	e := f.Enrichment
	if e.EPSSScore == nil || *e.EPSSScore != 0.3 || s.count("/epss") != 2 {
		t.Errorf("429 then 200 should succeed: %+v (calls %d)", e.EPSSScore, s.count("/epss"))
	}
	if e.RetrievalStatus["kev"] != "failed" || s.count("/kev") != 1+maxRetries {
		t.Errorf("persistent 429 must stop after %d retries and be recorded: %v (calls %d)", maxRetries, e.RetrievalStatus, s.count("/kev"))
	}
}

func TestStaleKEVConfirmsOnlyPositiveMatches(t *testing.T) {
	s := newServer(t)
	s.on("/epss", reply(200, `{"data": []}`))
	s.on("/kev", reply(500, ""))
	o := s.options(t)
	o.UseNVD, o.UseVulnrichment = false, false
	path := filepath.Join(o.CacheDir, "kev.json")
	_ = os.WriteFile(path, []byte(`{"CVE-2024-0001": {"cveID": "CVE-2024-0001"}}`), 0o600)
	old := time.Now().Add(-48 * time.Hour)
	_ = os.Chtimes(path, old, old)
	listed, absent := cveFinding("CVE-2024-0001"), cveFinding("CVE-2024-0002")
	if err := Enrich(context.Background(), []*model.Finding{listed, absent}, o); err != nil {
		t.Fatal(err)
	}
	if !listed.Enrichment.InCISAKEV || listed.Enrichment.RetrievalStatus["kev"] != "listed_stale" ||
		absent.Enrichment.InCISAKEV || absent.Enrichment.RetrievalStatus["kev"] != "unknown_stale" ||
		!strings.Contains(strings.Join(absent.Enrichment.Sources, ","), "kev:stale") {
		t.Errorf("listed %+v / absent %+v", listed.Enrichment, absent.Enrichment)
	}
}

func TestSnapshotExploitCoverageOnlyWithNVDRecord(t *testing.T) {
	found, missing, other := cveFinding("CVE-2024-0001"), cveFinding("CVE-2024-0002"), cveFinding("GHSA-xxxx")
	EnrichFromSnapshot([]*model.Finding{found, missing, other}, Snapshot{NVD: map[string]NVDEntry{"CVE-2024-0001": {References: []string{}}}})
	if strings.Join(found.Enrichment.ExploitSourcesChecked, ",") != "nvd:snapshot" || len(missing.Enrichment.ExploitSourcesChecked) != 0 {
		t.Errorf("found %v / missing %v", found.Enrichment.ExploitSourcesChecked, missing.Enrichment.ExploitSourcesChecked)
	}
	if other.Enrichment.RetrievalStatus["kev"] != "not_applicable" {
		t.Errorf("non-CVE ids are not looked up: %v", other.Enrichment.RetrievalStatus)
	}
}

// golden loads a Python golden report: the findings with their evidence
// cleared (to re-enrich) and the expected enrichment keyed by finding key.
func golden(t *testing.T, name string) ([]*model.Finding, map[string]any) {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/golden/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Findings []json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	var findings []*model.Finding
	want := map[string]any{}
	for _, item := range report.Findings {
		var f model.Finding
		var fields map[string]any
		_ = json.Unmarshal(item, &fields)
		want[fields["key"].(string)] = fields["enrichment"]
		// "<time>" placeholders and the evidence itself are re-derived.
		delete(fields, "first_seen")
		delete(fields, "enrichment")
		cleaned, _ := json.Marshal(fields)
		if err := json.Unmarshal(cleaned, &f); err != nil {
			t.Fatal(err)
		}
		f.Enrichment, f.Triage = model.Enrichment{}, nil
		findings = append(findings, &f)
	}
	return findings, want
}

func normalized(t *testing.T, e model.Enrichment) any {
	t.Helper()
	raw, _ := json.Marshal(e)
	var v map[string]any
	_ = json.Unmarshal(raw, &v)
	if v["enriched_at"] != nil {
		v["enriched_at"] = "<time>"
	}
	return v
}

func TestEnrichFromDemoSnapshotMatchesGolden(t *testing.T) {
	snapshot, err := DemoSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	findings, want := golden(t, "trivy.json")
	EnrichFromSnapshot(findings, snapshot)
	for _, f := range findings {
		if got := normalized(t, f.Enrichment); !reflect.DeepEqual(got, want[f.Key]) {
			t.Errorf("%s: got %v, want %v", f.Key, got, want[f.Key])
		}
	}
}

func TestEnrichFromSeededDemoCacheMatchesGolden(t *testing.T) {
	var calls int32
	offline := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		http.Error(w, "the demo must not need the network", http.StatusTeapot)
	}))
	defer offline.Close()
	dir := t.TempDir()
	if err := SeedDemoCache(dir); err != nil {
		t.Fatal(err)
	}
	findings, want := golden(t, "demo.json")
	o := Options{UseNVD: true, UseVulnrichment: true, CacheDir: dir, HTTP: offline.Client(), URLs: Endpoints{
		EPSS: offline.URL, KEV: offline.URL, NVD: offline.URL, CVERecord: offline.URL}}
	if err := Enrich(context.Background(), findings, o); err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if got := normalized(t, f.Enrichment); !reflect.DeepEqual(got, want[f.Key]) {
			t.Errorf("%s: got %v, want %v", f.Key, got, want[f.Key])
		}
	}
	if calls != 0 {
		t.Errorf("demo enrichment made %d network calls", calls)
	}
}
