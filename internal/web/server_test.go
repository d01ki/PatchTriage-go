package web

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type client struct {
	t    *testing.T
	base string
	http *http.Client
}

func newServerClient(t *testing.T) (*client, *httptest.Server) {
	t.Helper()
	store := &Store{Root: t.TempDir()}
	ts := httptest.NewServer(NewServer(store, &Runner{Store: store}))
	t.Cleanup(ts.Close)
	return newClientFor(t, ts), ts
}

func newClientFor(t *testing.T, ts *httptest.Server) *client {
	jar, _ := cookiejar.New(nil)
	return &client{t: t, base: ts.URL, http: &http.Client{Jar: jar}}
}

func (c *client) do(method, path string, body any, headers ...string) (int, []byte, http.Header) {
	c.t.Helper()
	var reader io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, c.base+path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw, resp.Header
}

func (c *client) json(method, path string, body any, want int) map[string]any {
	c.t.Helper()
	status, raw, _ := c.do(method, path, body)
	if status != want {
		c.t.Fatalf("%s %s = %d, want %d: %s", method, path, status, want, raw)
	}
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out
}

func TestIndexServesPageWithMatrix(t *testing.T) {
	c, _ := newServerClient(t)
	status, raw, headers := c.do("GET", "/", nil)
	page := string(raw)
	if status != 200 || !strings.HasPrefix(headers.Get("Content-Type"), "text/html") ||
		strings.Contains(page, "__HUMAN_IMPACT__") || strings.Contains(page, "__SSVC_LABELS__") ||
		!strings.Contains(page, `"catastrophic|degraded":"very_high"`) || !strings.Contains(page, `"mef_support_crippled":"MEF Support Crippled"`) {
		t.Errorf("index: %d %s", status, page[:200])
	}
	if !strings.Contains(headers.Get("Set-Cookie"), "patchtriage_session=") || !strings.Contains(headers.Get("Set-Cookie"), "HttpOnly") ||
		headers.Get("X-Frame-Options") != "DENY" || !strings.Contains(headers.Get("Content-Security-Policy"), "default-src 'self'") {
		t.Errorf("security headers: %v", headers)
	}
}

func TestConfigAdvertisesPhase1(t *testing.T) {
	c, _ := newServerClient(t)
	cfg := c.json("GET", "/api/config", nil, 200)
	backends, _ := json.Marshal(cfg["backends"])
	caps, _ := json.Marshal(cfg["capabilities"])
	limits := cfg["limits"].(map[string]any)
	if string(backends) != `["rules"]` || strings.Contains(string(caps), "fleet-import") ||
		strings.Contains(string(caps), "github-repository-sbom") || cfg["ui_schema_version"] != 2.0 ||
		limits["targets"] != 25.0 || limits["ssvc_review_rows"] != 250.0 || cfg["has_ai"] != false {
		t.Errorf("config = %v", cfg)
	}
}

func waitJob(t *testing.T, c *client, id string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		job := c.json("GET", "/api/jobs/"+id, nil, 200)
		if state := job["state"]; state == "succeeded" || state == "failed" {
			return job
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("job did not finish")
	return nil
}

func TestDemoRunFlow(t *testing.T) {
	c, _ := newServerClient(t)
	target := c.json("POST", "/api/demo", map[string]any{}, 201)
	id := target["id"].(string)
	if target["source_file"] != true || target["ssvc_overrides"] != nil || target["name"] != "Demo" {
		t.Errorf("public target = %v", target)
	}
	again := c.json("POST", "/api/demo", map[string]any{}, 200)
	if again["id"] != id {
		t.Error("the demo target is reused")
	}
	job := c.json("POST", "/api/targets/"+id+"/runs", map[string]any{"backend": "rules"}, 202)
	finished := waitJob(t, c, job["job_id"].(string))
	if finished["state"] != "succeeded" || finished["workspace"] != nil {
		t.Fatalf("job = %v", finished)
	}
	outcomes := finished["summary"].(map[string]any)["outcomes"].(map[string]any)
	if outcomes["immediate"] != 1.0 || outcomes["out_of_cycle"] != 1.0 || outcomes["scheduled"] != 2.0 {
		t.Errorf("outcomes = %v", outcomes)
	}
	status, raw, _ := c.do("GET", "/api/summaries", nil)
	if status != 200 || !strings.Contains(string(raw), `"result_state":"assessed"`) {
		t.Errorf("summaries: %d %s", status, raw[:min(200, len(raw))])
	}
	status, report, _ := c.do("GET", "/report/"+id, nil)
	if status != 200 || !strings.Contains(string(report), "PatchTriage - Demo") {
		t.Errorf("report: %d", status)
	}
	status, latest, _ := c.do("GET", "/api/jobs?latest=1", nil)
	if status != 200 || !strings.Contains(string(latest), job["job_id"].(string)) {
		t.Errorf("latest jobs: %s", latest)
	}
	fleet := c.json("GET", "/api/fleet/summary", nil, 200)
	if fleet["targets_assessed"] != 1.0 {
		t.Errorf("fleet = %v", fleet)
	}
	sync := c.json("POST", "/api/targets/"+id+"/run", map[string]any{}, 200)
	if sync["total"] != 4.0 {
		t.Errorf("synchronous run = %v", sync["total"])
	}
}

func TestServerRejectsOversizeAndForeignSession(t *testing.T) {
	t.Setenv("PATCHTRIAGE_MAX_REQUEST_BYTES", "200")
	c, ts := newServerClient(t)
	if status, _, _ := c.do("POST", "/api/targets", map[string]any{"name": strings.Repeat("x", 500)}); status != 413 {
		t.Errorf("oversize body = %d, want 413", status)
	}
	target := c.json("POST", "/api/targets", map[string]any{"name": "mine"}, 201)
	id := target["id"].(string)
	other := newClientFor(t, ts)
	if status, _, _ := other.do("POST", "/api/targets/"+id+"/context", map[string]any{"system_exposure": "small"}); status != 404 {
		t.Errorf("foreign session context update = %d, want 404", status)
	}
	if status, _, _ := other.do("GET", "/report/"+id, nil); status != 404 {
		t.Errorf("foreign session report = %d, want 404", status)
	}
	if status, raw, _ := other.do("GET", "/api/targets", nil); status != 200 || string(raw) != "[]" {
		t.Errorf("foreign session lists %s", raw)
	}
	if status, _, _ := c.do("POST", "/api/targets", map[string]any{"name": "x"}, "Origin", "http://evil.example"); status != 403 {
		t.Errorf("cross-origin write = %d, want 403", status)
	}
	req, _ := http.NewRequest("POST", ts.URL+"/api/targets", strings.NewReader(`{"name":"x"}`))
	req.Header.Set("Content-Type", "text/plain")
	if resp, err := c.http.Do(req); err != nil || resp.StatusCode != 415 {
		t.Errorf("non-JSON body accepted: %v", resp.StatusCode)
	}
	if status, _, _ := c.do("POST", "/api/targets", map[string]any{"name": "y", "system_exposure": "public"}); status != 400 {
		t.Errorf("invalid context = %d, want 400", status)
	}
}

func TestUnportedEndpointsReturn501(t *testing.T) {
	c, _ := newServerClient(t)
	target := c.json("POST", "/api/targets", map[string]any{"name": "repo"}, 201)
	for _, path := range []string{"/api/targets/" + target["id"].(string) + "/repository", "/api/fleet/import"} {
		status, raw, _ := c.do("POST", path, map[string]any{"repository_url": "https://github.com/x/y", "owner_url": "https://github.com/x"})
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		if status != 501 || !strings.Contains(strings.ToLower(body["error"].(string)), "not available") {
			t.Errorf("%s = %d %s", path, status, raw)
		}
	}
}

func TestUploadAndInvalidation(t *testing.T) {
	c, _ := newServerClient(t)
	target := c.json("POST", "/api/targets", map[string]any{"name": "svc", "system_exposure": "open"}, 201)
	id := target["id"].(string)
	if status, _, _ := c.do("POST", "/api/targets/"+id+"/runs", map[string]any{}); status != 400 {
		t.Errorf("run without evidence = %d, want 400", status)
	}
	if status, _, _ := c.do("POST", "/api/targets/"+id+"/source", map[string]any{"content": `{"foo": 1}`}); status != 400 {
		t.Errorf("unrecognized evidence = %d, want 400", status)
	}
	trivy := `{"SchemaVersion": 2, "ArtifactName": "svc", "Results": []}`
	upload := c.json("POST", "/api/targets/"+id+"/source", map[string]any{"content": trivy, "filename": "t.json"}, 200)
	if upload["format"] != "trivy" || upload["ok"] != true {
		t.Errorf("upload = %v", upload)
	}
	demo := c.json("POST", "/api/demo", map[string]any{}, 201)
	demoID := demo["id"].(string)
	job := c.json("POST", "/api/targets/"+demoID+"/runs", map[string]any{}, 202)
	finished := waitJob(t, c, job["job_id"].(string))
	key := finished["summary"].(map[string]any)["ssvc_inputs"].([]any)[0].(map[string]any)["finding_key"]
	result := c.json("POST", "/api/targets/"+demoID+"/ssvc-inputs", map[string]any{"inputs": []any{
		map[string]any{"finding_key": key, "exploitation": "auto", "automatable": "no"}}}, 200)
	if result["overrides"] != 1.0 {
		t.Errorf("overrides = %v", result)
	}
	if status, raw, _ := c.do("GET", "/api/summaries", nil); status != 200 || string(raw) != "[]" {
		t.Errorf("changed SSVC inputs must invalidate the summary: %s", raw[:min(100, len(raw))])
	}
	if status, _, _ := c.do("POST", "/api/targets/"+demoID+"/ssvc-inputs", map[string]any{"inputs": []any{
		map[string]any{"finding_key": key, "automatable": "maybe"}}}); status != 400 {
		t.Errorf("invalid SSVC input = %d, want 400", status)
	}
	if status, _, _ := c.do("DELETE", "/api/targets/"+id, nil); status != 204 {
		t.Errorf("delete = %d", status)
	}
	if status, _, _ := c.do("DELETE", "/api/targets/"+id, nil); status != 404 {
		t.Errorf("second delete = %d", status)
	}
}
