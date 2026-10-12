package enrich

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/d01ki/PatchTriage-go/internal/decision"
	"github.com/d01ki/PatchTriage-go/internal/model"
)

const log4shell = "CVE-2021-44228"

func vendorFinding(ecosystem, purl string) *model.Finding {
	score := 10.0
	asset := model.NewAsset("checkout")
	asset.Kind = "repository"
	return &model.Finding{Key: "finding-1", VulnID: log4shell, CVSSScore: &score, Asset: asset,
		Package: model.Package{Name: "log4j-core", Version: "2.14.1", Ecosystem: ecosystem, Purl: purl}}
}

func log4jFinding() *model.Finding {
	return vendorFinding("maven", "pkg:maven/org.apache.logging.log4j/log4j-core")
}

var vendorPayloads = map[string]string{
	"msrc": `{"value": [{"ID": "2021-Dec", "DocumentTitle": "December 2021 Security Updates",
		"InitialReleaseDate": "2021-12-14T08:00:00Z", "CvrfUrl": "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2021-Dec"}]}`,
	"rhsa": `[{"RHSA": "RHSA-2021:5206", "severity": "important", "released_on": "2021-12-15T00:00:00Z",
		"CVEs": ["CVE-2021-44228"], "released_packages": ["log4j-core-2.16.0-1.el8"]}]`,
	"usn": `{"id": "UBUNTU-CVE-2021-44228", "summary": "Log4j vulnerability", "published": "2021-12-13T00:00:00Z",
		"related": ["USN-5192-1"], "references": [{"type": "ADVISORY", "url": "https://ubuntu.com/security/notices/USN-5192-1"}],
		"affected": [{"package": {"name": "apache-log4j2"}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.15.0-0.21.04.1"}]}]}]}`,
	"debian": `{"apache-log4j2": {"CVE-2021-44228": {"description": "Apache Log4j2 remote code execution",
		"releases": {"bookworm": {"status": "resolved", "fixed_version": "2.17.1-1", "urgency": "high"}}}}}`,
	"ghsa": `[{"ghsa_id": "GHSA-jfh8-c2jp-5v3q", "cve_id": "CVE-2021-44228", "html_url": "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q",
		"summary": "Log4Shell", "severity": "critical", "published_at": "2021-12-10T00:00:00Z",
		"vulnerabilities": [{"package": {"ecosystem": "maven", "name": "log4j-core"}, "first_patched_version": "2.15.0",
		"vulnerable_functions": ["JndiManager.lookup"]}]}]`,
}

func exploitDBPayload(number, id string) string {
	return `{"draw": 1, "recordsTotal": 2, "recordsFiltered": 2, "data": [
		{"id": "` + id + `", "description": ["` + id + `", "Apache Log4j 2 - RCE"], "date_published": "2021-12-14",
		 "verified": 1, "type": {"display": "Remote"}, "platform": {"platform": "Java"},
		 "code": [{"code_type": "cve", "code": "` + number + `"}]},
		{"id": "1", "description": ["1", "Other"], "verified": 0, "code": [{"code_type": "cve", "code": "2020-0001"}]}]}`
}

func TestEachOfficialFeedIsNormalized(t *testing.T) {
	parse := func(f func([]byte, string) ([]model.VendorAdvisory, error), source string) model.VendorAdvisory {
		rows, err := f([]byte(vendorPayloads[source]), log4shell)
		if err != nil || len(rows) == 0 {
			t.Fatalf("%s: %v %v", source, rows, err)
		}
		return rows[0]
	}
	if a := parse(parseMSRC, "msrc"); a.AdvisoryID != "2021-Dec" || a.URL != "https://msrc.microsoft.com/update-guide/vulnerability/"+log4shell {
		t.Errorf("msrc = %+v", a)
	}
	if a := parse(parseRHSA, "rhsa"); a.AdvisoryID != "RHSA-2021:5206" || strings.Join(a.FixedVersions, ",") != "log4j-core-2.16.0-1.el8" {
		t.Errorf("rhsa = %+v", a)
	}
	if a := parse(parseUSN, "usn"); a.AdvisoryID != "USN-5192-1" || !contains(a.FixedVersions, "apache-log4j2 2.15.0-0.21.04.1") {
		t.Errorf("usn = %+v", a)
	}
	if a := parse(parseDebian, "debian"); strings.Join(a.FixedVersions, ",") != "apache-log4j2 bookworm: 2.17.1-1" || a.Severity != "high" {
		t.Errorf("debian = %+v", a)
	}
	if a := parse(parseGHSA, "ghsa"); a.AdvisoryID != "GHSA-jfh8-c2jp-5v3q" || strings.Join(a.VulnerableFunctions, ",") != "JndiManager.lookup" {
		t.Errorf("ghsa = %+v", a)
	}
}

func TestExploitDBKeepsExactCVEHits(t *testing.T) {
	rows, err := parseExploitDB([]byte(exploitDBPayload("2021-44228", "50592")), log4shell)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows = %v %v", rows, err)
	}
	r := rows[0]
	if r.AdvisoryID != "EDB-50592" || r.URL != "https://www.exploit-db.com/exploits/50592" ||
		r.Title != "Apache Log4j 2 - RCE" || r.Severity != "verified" || strings.Join(r.Products, ",") != "Java,Remote" {
		t.Errorf("record = %+v", r)
	}
	if _, err := parseExploitDB([]byte(`{"error": "blocked"}`), log4shell); err == nil || !strings.Contains(err.Error(), "unexpected search response") {
		t.Errorf("err = %v", err)
	}
}

func TestSourceSelectionAndValidation(t *testing.T) {
	if got := AutoSources(log4jFinding()); strings.Join(got, ",") != "rhsa,msrc,exploitdb,ghsa" {
		t.Errorf("maven auto = %v", got)
	}
	if got := AutoSources(vendorFinding("ubuntu", "pkg:deb/ubuntu/apache-log4j2")); strings.Join(got, ",") != "rhsa,msrc,exploitdb,usn" {
		t.Errorf("ubuntu auto = %v", got)
	}
	if all, _ := ParseSources("all"); strings.Join(all, ",") != "msrc,rhsa,usn,debian,ghsa,exploitdb" {
		t.Errorf("all = %v", all)
	}
	if _, err := ParseSources("oracle"); err == nil || !strings.Contains(err.Error(), "unknown vendor source") {
		t.Errorf("oracle err = %v", err)
	}
	if _, err := ParseSources("auto,ghsa"); err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Errorf("auto,ghsa err = %v", err)
	}
}

type vendorServer struct {
	*httptest.Server
	mu       sync.Mutex
	exploits []string
}

func newVendorServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) (*vendorServer, Options) {
	vs := &vendorServer{}
	vs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/exploitdb") {
			vs.mu.Lock()
			vs.exploits = append(vs.exploits, r.URL.Query().Get("cve"))
			vs.mu.Unlock()
		}
		handler(w, r)
	}))
	t.Cleanup(vs.Close)
	return vs, Options{CacheDir: t.TempDir(), HTTP: vs.Client(), URLs: Endpoints{
		MSRC: vs.URL + "/msrc/", RHSA: vs.URL + "/rhsa", UbuntuOSV: vs.URL + "/ubuntu/UBUNTU-",
		Debian: vs.URL + "/debian", GHSA: vs.URL + "/ghsa", ExploitDB: vs.URL + "/exploitdb"}}
}

func TestAllConnectorsAttachEvidence(t *testing.T) {
	_, o := newVendorServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/msrc/"+log4shell:
			_, _ = w.Write([]byte(vendorPayloads["msrc"]))
		case r.URL.Path == "/rhsa":
			_, _ = w.Write([]byte(vendorPayloads["rhsa"]))
		case r.URL.Path == "/ubuntu/UBUNTU-"+log4shell:
			_, _ = w.Write([]byte(vendorPayloads["usn"]))
		case r.URL.Path == "/debian":
			_, _ = w.Write([]byte(vendorPayloads["debian"]))
		case r.URL.Path == "/ghsa":
			_, _ = w.Write([]byte(vendorPayloads["ghsa"]))
		case r.URL.Path == "/exploitdb":
			_, _ = w.Write([]byte(exploitDBPayload("2021-44228", "50592")))
		default:
			http.NotFound(w, r)
		}
	})
	f := log4jFinding()
	o.VendorSources = "all"
	summary, err := enrichVendors(context.Background(), []*model.Finding{f}, o)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"sources": []string{"msrc", "rhsa", "usn", "debian", "ghsa", "exploitdb"},
		"checked_cves": 1, "advisories": 6, "errors": 0, "truncated": 0}
	if !reflect.DeepEqual(summary, want) {
		t.Errorf("summary = %v", summary)
	}
	e := f.Enrichment
	if strings.Join(e.VendorSourcesChecked, ",") != "msrc,rhsa,usn,debian,ghsa,exploitdb" || len(e.VendorLookupErrors) != 0 {
		t.Errorf("enrichment = %+v", e)
	}
	var sources []string
	for _, a := range e.VendorAdvisories {
		sources = append(sources, a.Source)
	}
	sort.Strings(sources)
	if strings.Join(sources, ",") != "debian,exploitdb,ghsa,msrc,rhsa,usn" {
		t.Errorf("advisory sources = %v", sources)
	}
	// The vendor cache is reused, so the next run makes no new RHSA/Debian calls.
}

func TestConnectorFailureIsVisibleButNonFatal(t *testing.T) {
	_, o := newVendorServer(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message": "maintenance"}`, http.StatusServiceUnavailable)
	})
	f := log4jFinding()
	o.VendorSources = "ghsa"
	summary, _ := enrichVendors(context.Background(), []*model.Finding{f}, o)
	if summary["errors"] != 1 || len(f.Enrichment.VendorAdvisories) != 0 ||
		strings.Join(f.Enrichment.VendorSourcesChecked, ",") != "ghsa" || len(f.Enrichment.VendorLookupErrors) == 0 {
		t.Errorf("summary %v / enrichment %+v", summary, f.Enrichment)
	}
}

func TestExploitDBIsLiveAndNeverPersisted(t *testing.T) {
	vs, o := newVendorServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cve") == "2021-44228" {
			_, _ = w.Write([]byte(exploitDBPayload("2021-44228", "50592")))
			return
		}
		_, _ = w.Write([]byte(`{"draw": 1, "data": []}`))
	})
	hit, miss := log4jFinding(), log4jFinding()
	miss.VulnID = "CVE-2020-0002"
	o.VendorSources = "exploitdb"
	for run := 0; run < 2; run++ {
		for _, f := range []*model.Finding{hit, miss} {
			f.Enrichment.ExploitRefs, f.Enrichment.ExploitSourcesChecked, f.Enrichment.VendorAdvisories = nil, nil, nil
		}
		if _, err := enrichVendors(context.Background(), []*model.Finding{hit, miss}, o); err != nil {
			t.Fatal(err)
		}
	}
	sort.Strings(vs.exploits)
	if strings.Join(vs.exploits, ",") != "2020-0002,2020-0002,2021-44228,2021-44228" {
		t.Errorf("Exploit-DB must be searched on every run: %v", vs.exploits)
	}
	if strings.Join(hit.Enrichment.ExploitRefs, ",") != "https://www.exploit-db.com/exploits/50592" ||
		!contains(hit.Enrichment.ExploitSourcesChecked, "exploitdb") ||
		len(miss.Enrichment.ExploitRefs) != 0 || !contains(miss.Enrichment.ExploitSourcesChecked, "exploitdb") {
		t.Errorf("hit %+v / miss %+v", hit.Enrichment, miss.Enrichment)
	}
	if stored, err := os.ReadFile(filepath.Join(o.CacheDir, "vendor_advisories.json")); err == nil && strings.Contains(string(stored), "exploitdb") {
		t.Error("Exploit-DB results must never be written to disk")
	}
	if a := decision.Assess(hit); a.Exploitation.Value != "public_poc" {
		t.Errorf("an Exploit-DB hit is public PoC evidence: %s", a.Exploitation.Value)
	}
}

func TestPerCVELookupsOverlapWithinBound(t *testing.T) {
	var mu sync.Mutex
	active, peak := 0, 0
	_, o := newVendorServer(t, func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		active++
		peak = max(peak, active)
		mu.Unlock()
		time.Sleep(50 * time.Millisecond)
		mu.Lock()
		active--
		mu.Unlock()
		_, _ = w.Write([]byte(`{"draw": 1, "data": []}`))
	})
	var findings []*model.Finding
	for n := 0; n < 12; n++ {
		f := log4jFinding()
		f.VulnID = "CVE-2020-" + strings.Repeat("0", 3) + string(rune('a'+n))
		findings = append(findings, f)
	}
	o.VendorSources = "exploitdb"
	summary, _ := enrichVendors(context.Background(), findings, o)
	if summary["errors"] != 0 || peak <= 1 || peak > perCVEConcurrency {
		t.Errorf("summary %v, peak concurrency %d (bound %d)", summary, peak, perCVEConcurrency)
	}
}

func TestFailedExploitDBSearchIsNotCoverage(t *testing.T) {
	_, o := newVendorServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})
	f := log4jFinding()
	o.VendorSources = "exploitdb"
	summary, _ := enrichVendors(context.Background(), []*model.Finding{f}, o)
	if summary["errors"] != 1 || contains(f.Enrichment.ExploitSourcesChecked, "exploitdb") || len(f.Enrichment.VendorLookupErrors) == 0 {
		t.Errorf("summary %v / enrichment %+v", summary, f.Enrichment)
	}
}

func TestMSRC404IsNoRecord(t *testing.T) {
	_, o := newVendorServer(t, func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	f := log4jFinding()
	o.VendorSources = "msrc"
	summary, _ := enrichVendors(context.Background(), []*model.Finding{f}, o)
	if summary["errors"] != 0 || len(f.Enrichment.VendorLookupErrors) != 0 {
		t.Errorf("summary %v / errors %v", summary, f.Enrichment.VendorLookupErrors)
	}
}

func TestVendorLookupLimit(t *testing.T) {
	_, o := newVendorServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"draw": 1, "data": []}`))
	})
	findings := []*model.Finding{}
	for n := 0; n < maxVendorCVEs+2; n++ {
		f := log4jFinding()
		raw, _ := json.Marshal(n)
		f.VulnID = "CVE-2020-1" + strings.Repeat("0", 3-len(raw)) + string(raw)
		findings = append(findings, f)
	}
	o.VendorSources = "exploitdb"
	summary, _ := enrichVendors(context.Background(), findings, o)
	limited := 0
	for _, f := range findings {
		if contains(f.Enrichment.VendorLookupErrors, "vendor: lookup limit 50 reached") {
			limited++
		}
	}
	if summary["truncated"] != 2 || limited != 2 {
		t.Errorf("summary %v, limited %d", summary, limited)
	}
}
