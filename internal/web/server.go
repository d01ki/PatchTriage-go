package web

// The HTTP server behind the single-page console. Same paths, payloads and
// security behavior as the Python server: anonymous HttpOnly session
// workspaces, bounded request/evidence sizes, asynchronous jobs with bounded
// concurrency, and same-origin writes only.

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/d01ki/PatchTriage-go/internal/decision"
	"github.com/d01ki/PatchTriage-go/internal/ingest"
	"github.com/d01ki/PatchTriage-go/internal/repository"
)

//go:embed page.html
var pageTemplate string

const (
	sessionCookie = "patchtriage_session"
	sessionTTL    = 6 * time.Hour
	appVersion    = "0.6.0-go"
)

var (
	jobPath    = regexp.MustCompile(`^/api/jobs/([0-9a-f]{24})$`)
	reportPath = regexp.MustCompile(`^/report/([0-9a-f]{12})$`)
	targetPath = regexp.MustCompile(`^/api/targets/([0-9a-f]{12})(?:/(context|ssvc-inputs|source|repository|runs|run))?$`)
)

func envInt(name string, fallback int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil {
		return v
	}
	return fallback
}

type limits struct {
	requestBytes, sourceBytes, sessionSourceBytes int64
	targets, jobsPerSession, jobsGlobal           int
	retainedJobs, fleetImportRepos                int
}

func limitsFromEnv() limits {
	return limits{
		requestBytes:       int64(envInt("PATCHTRIAGE_MAX_REQUEST_BYTES", 20<<20)),
		sourceBytes:        int64(envInt("PATCHTRIAGE_MAX_SOURCE_BYTES", 16<<20)),
		sessionSourceBytes: int64(envInt("PATCHTRIAGE_MAX_SESSION_SOURCE_BYTES", 64<<20)),
		targets:            envInt("PATCHTRIAGE_MAX_TARGETS", 25),
		jobsPerSession:     envInt("PATCHTRIAGE_MAX_ACTIVE_JOBS_PER_SESSION", 3),
		jobsGlobal:         envInt("PATCHTRIAGE_MAX_ACTIVE_JOBS_GLOBAL", 20),
		retainedJobs:       envInt("PATCHTRIAGE_MAX_RETAINED_JOBS", 500),
		fleetImportRepos:   envInt("PATCHTRIAGE_MAX_FLEET_IMPORT_REPOS", 15),
	}
}

type job map[string]any

// Server is the GUI HTTP handler.
type Server struct {
	store    *Store
	runner   *Runner
	limits   limits
	page     []byte
	mu       sync.Mutex
	jobs     map[string]job
	runSlots chan struct{}
	runLocks sync.Map // workspace|target -> *sync.Mutex
	// Repository acquires evidence for repository URLs; tests point it at
	// local servers.
	Repository  repository.Acquirer
	importSlots chan struct{}
}

// NewServer builds the handler; limits come from the environment.
func NewServer(store *Store, runner *Runner) *Server {
	labels := map[string]string{}
	for _, values := range [][]string{toStrings(decision.SystemExposures), toStrings(decision.MissionImpacts),
		toStrings(decision.SafetyImpacts), toStrings(decision.HumanImpacts)} {
		for _, v := range values {
			labels[v] = decision.LabelFor(v)
		}
	}
	matrix := map[string]string{}
	for _, s := range decision.SafetyImpacts {
		for _, m := range decision.MissionImpacts {
			matrix[string(s)+"|"+string(m)] = string(decision.DeriveHumanImpact(m, s))
		}
	}
	labelJSON, _ := json.Marshal(labels)
	matrixJSON, _ := json.Marshal(matrix)
	page := strings.NewReplacer("__SSVC_LABELS__", string(labelJSON), "__HUMAN_IMPACT__", string(matrixJSON)).Replace(pageTemplate)
	return &Server{store: store, runner: runner, limits: limitsFromEnv(), page: []byte(page), jobs: map[string]job{},
		runSlots:    make(chan struct{}, max(1, envInt("PATCHTRIAGE_MAX_CONCURRENT_RUNS", 2))),
		importSlots: make(chan struct{}, max(1, envInt("PATCHTRIAGE_MAX_CONCURRENT_IMPORTS", 2)))}
}

func toStrings[T ~string](values []T) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = string(v)
	}
	return out
}

type requestError struct {
	status  int
	message string
}

func (e *requestError) Error() string { return e.message }

func badRequest(status int, message string) error { return &requestError{status, message} }

func publicMode() bool {
	return strings.ToLower(envOr("PATCHTRIAGE_DEPLOYMENT_MODE", "local")) == "public"
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// exceptionMessage avoids exposing server paths on a public deployment.
func exceptionMessage(err error) string {
	if publicMode() {
		return "assessment failed; retry or use a local deployment for diagnostics"
	}
	return err.Error()
}

// ------------------------------------------------------------ session

func (s *Server) workspace(w http.ResponseWriter, r *http.Request) string {
	value := ""
	if c, err := r.Cookie(sessionCookie); err == nil {
		value = c.Value
	}
	if !workspaceIDPattern.MatchString(value) {
		value = randomHex(16)
		s.cleanupExpired()
	}
	s.store.Touch(value)
	secure := false
	switch strings.ToLower(envOr("PATCHTRIAGE_COOKIE_SECURE", "auto")) {
	case "true":
		secure = true
	case "false":
	default:
		proto := strings.ToLower(strings.TrimSpace(strings.SplitN(r.Header.Get("X-Forwarded-Proto"), ",", 2)[0]))
		secure = proto == "https"
	}
	cookie := fmt.Sprintf("%s=%s; Path=/; Max-Age=%d; HttpOnly; SameSite=Strict", sessionCookie, value, int(sessionTTL.Seconds()))
	if secure {
		cookie += "; Secure"
	}
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Set-Cookie", cookie)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	h.Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self' data:; "+
		"style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; "+
		"frame-ancestors 'none'; form-action 'self'")
	return value
}

func (s *Server) cleanupExpired() {
	s.mu.Lock()
	active := map[string]bool{}
	for _, j := range s.jobs {
		if j["state"] == "queued" || j["state"] == "running" {
			active[j["workspace"].(string)] = true
		}
	}
	s.mu.Unlock()
	s.store.Cleanup(sessionTTL, active)
}

// ------------------------------------------------------------ helpers

func sendJSON(w http.ResponseWriter, status int, value any) {
	raw, _ := json.Marshal(value)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

func sendError(w http.ResponseWriter, status int, message string) {
	sendJSON(w, status, map[string]string{"error": message})
}

func (s *Server) readJSON(r *http.Request) (map[string]any, error) {
	if ct := strings.ToLower(strings.TrimSpace(strings.SplitN(r.Header.Get("Content-Type"), ";", 2)[0])); ct != "application/json" {
		return nil, badRequest(415, "Content-Type must be application/json")
	}
	if r.ContentLength > s.limits.requestBytes {
		return nil, badRequest(413, "request body is too large")
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, s.limits.requestBytes+1))
	if err != nil {
		return nil, badRequest(400, "request body could not be read")
	}
	if int64(len(raw)) > s.limits.requestBytes {
		return nil, badRequest(413, "request body is too large")
	}
	if len(raw) == 0 {
		return map[string]any{}, nil
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil || body == nil {
		return nil, badRequest(400, "request body must be a JSON object")
	}
	return body, nil
}

// originAllowed rejects browser cross-site writes and allows non-browser clients.
func originAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	return err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && strings.EqualFold(parsed.Host, r.Host)
}

// publicTarget hides server paths and analyst overrides from the GUI.
func publicTarget(t Target) Target {
	out := copyMap(t)
	out["source_file"] = strOf(t["source_file"]) != ""
	delete(out, "ssvc_overrides")
	return out
}

func detectFormat(content string) string {
	raw := []byte(content)
	if !json.Valid(raw) {
		return ""
	}
	if kind := ingest.IsSBOM(raw); kind != "" {
		return kind
	}
	return ingest.SniffFormat(raw)
}

// ------------------------------------------------------------ jobs

func (s *Server) runLock(ws, id string) *sync.Mutex {
	lock, _ := s.runLocks.LoadOrStore(ws+"|"+id, &sync.Mutex{})
	return lock.(*sync.Mutex)
}

func (s *Server) pruneJobsLocked() {
	cutoff := float64(time.Now().Add(-sessionTTL).Unix())
	var terminal []string
	for id, j := range s.jobs {
		if j["state"] == "succeeded" || j["state"] == "failed" {
			if f, _ := j["finished_at"].(float64); f < cutoff {
				delete(s.jobs, id)
				continue
			}
			terminal = append(terminal, id)
		}
	}
	sort.Slice(terminal, func(a, b int) bool {
		fa, _ := s.jobs[terminal[a]]["finished_at"].(float64)
		fb, _ := s.jobs[terminal[b]]["finished_at"].(float64)
		return fa > fb
	})
	for _, id := range terminal[min(len(terminal), max(1, s.limits.retainedJobs)):] {
		delete(s.jobs, id)
	}
}

func now() float64 { return float64(time.Now().UnixNano()) / 1e9 }

func (s *Server) execute(id string) {
	s.mu.Lock()
	j := s.jobs[id]
	ws, targetID := j["workspace"].(string), j["target_id"].(string)
	s.mu.Unlock()
	finish := func(err error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if j, ok := s.jobs[id]; ok {
			if err != nil {
				j["state"], j["error"] = "failed", exceptionMessage(err)
			} else {
				j["state"] = "succeeded"
			}
			j["finished_at"] = now()
			s.pruneJobsLocked()
		}
	}
	s.runSlots <- struct{}{}
	defer func() { <-s.runSlots }()
	s.mu.Lock()
	j["state"], j["started_at"] = "running", now()
	s.mu.Unlock()
	target, err := s.store.Get(ws, targetID)
	if err != nil {
		finish(errors.New("target was deleted before the run started"))
		return
	}
	lock := s.runLock(ws, targetID)
	lock.Lock()
	_, err = s.runner.Run(context.Background(), ws, target)
	lock.Unlock()
	finish(err)
}

func (s *Server) startJob(ws string, target Target) (job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneJobsLocked()
	id := strOf(target["id"])
	active, mine := 0, 0
	for _, j := range s.jobs {
		if j["state"] == "queued" || j["state"] == "running" {
			if j["workspace"] == ws && j["target_id"] == id {
				return j, nil
			}
			active++
			if j["workspace"] == ws {
				mine++
			}
		}
	}
	if active >= s.limits.jobsGlobal {
		return nil, badRequest(429, "assessment queue is full; retry later")
	}
	if mine >= s.limits.jobsPerSession {
		return nil, badRequest(429, "anonymous workspace assessment limit reached; wait for an active run to finish")
	}
	jobID := randomHex(12)
	j := job{"job_id": jobID, "workspace": ws, "target_id": id, "backend": "rules", "state": "queued",
		"created_at": now(), "input_revision": intOf(target["input_revision"]), "source_sha256": strOf(target["source_sha256"])}
	s.jobs[jobID] = j
	go s.execute(jobID)
	return j, nil
}

// publicJob snapshots a job without its workspace and attaches the summary
// of a succeeded run.
func (s *Server) publicJob(j job) map[string]any {
	s.mu.Lock()
	snapshot := copyMap(j)
	s.mu.Unlock()
	ws := strOf(snapshot["workspace"])
	delete(snapshot, "workspace")
	if snapshot["state"] == "succeeded" {
		if summary := s.store.LoadSummary(ws, strOf(snapshot["target_id"])); summary != nil {
			snapshot["summary"] = summary
		} else {
			snapshot["state"], snapshot["error"] = "failed", "completed assessment summary is unavailable"
		}
	}
	return snapshot
}

// ------------------------------------------------------------ routing

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if recovered := recover(); recovered != nil {
			sendError(w, 500, exceptionMessage(fmt.Errorf("%v", recovered)))
		}
	}()
	ws := s.workspace(w, r)
	var err error
	switch r.Method {
	case http.MethodGet:
		err = s.get(w, r, ws)
	case http.MethodPost, http.MethodDelete:
		if !originAllowed(r) {
			sendError(w, 403, "cross-origin request rejected")
			return
		}
		if r.Method == http.MethodPost {
			err = s.post(w, r, ws)
		} else {
			err = s.delete(w, r, ws)
		}
	default:
		sendError(w, 405, "method not allowed")
		return
	}
	var re *requestError
	switch {
	case errors.As(err, &re):
		sendError(w, re.status, re.message)
	case err != nil:
		sendError(w, 500, exceptionMessage(err))
	}
}

// githubImportToken keeps the anonymous hosted importer strictly
// public-only: a token configured for enrichment can also read private
// repositories, so public mode never passes it to the importer.
func githubImportToken() string {
	if publicMode() {
		return ""
	}
	return envOr("GITHUB_TOKEN", os.Getenv("GH_TOKEN"))
}

func (s *Server) config() map[string]any {
	generic := "unavailable"
	if repository.GenericEnabled() {
		generic = "local-osv-scanner"
	}
	token := "public-rate-limit"
	if envOr("GITHUB_TOKEN", os.Getenv("GH_TOKEN")) != "" {
		token = "token"
	}
	return map[string]any{
		"backends": []string{"rules"}, "has_key": false, "has_ai": false, "ai_provider": nil,
		"capabilities": []string{"offline-demo", "ssvc-deployer", "epss-baseline", "kev-baseline", "reachability",
			"runtime-context", "vendor-advisories", "async-runs", "github-repository-sbom", "fleet-import"},
		"version": appVersion, "build_sha": envOr("PATCHTRIAGE_BUILD_SHA", "development"), "ui_schema_version": 2,
		"deployment_mode": envOr("PATCHTRIAGE_DEPLOYMENT_MODE", "local"),
		"repository_import": map[string]any{"github": "dependency-graph-sbom",
			"github_private_with_token": githubImportToken() != "", "generic_https_git": generic,
			"executes_repository_code": false},
		"data_isolation": "anonymous-session", "retention_hours": int(sessionTTL.Hours()),
		"limits": map[string]any{"targets": s.limits.targets, "source_bytes": s.limits.sourceBytes,
			"session_source_bytes": s.limits.sessionSourceBytes, "active_jobs_per_session": s.limits.jobsPerSession,
			"ssvc_review_rows": maxWebSSVCInputs, "fleet_import_repos": s.limits.fleetImportRepos},
		"connectors": map[string]string{"msrc": "public", "rhsa": "public", "usn": "public", "debian": "public", "ghsa": token},
	}
}

func (s *Server) get(w http.ResponseWriter, r *http.Request, ws string) error {
	switch path := r.URL.Path; path {
	case "/":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(s.page)
		return nil
	case "/api/config":
		sendJSON(w, 200, s.config())
		return nil
	case "/api/targets":
		targets, err := s.store.Load(ws)
		if err != nil {
			return err
		}
		out := []Target{}
		for _, t := range targets {
			out = append(out, publicTarget(t))
		}
		sendJSON(w, 200, out)
		return nil
	case "/api/summaries":
		targets, err := s.store.Load(ws)
		if err != nil {
			return err
		}
		out := []map[string]any{}
		for _, t := range targets {
			if summary := s.store.LoadSummary(ws, strOf(t["id"])); summary != nil {
				out = append(out, summary)
			}
		}
		sendJSON(w, 200, out)
		return nil
	case "/api/fleet/summary":
		fleet, err := AggregateFleet(s.store, ws)
		if err != nil {
			return err
		}
		sendJSON(w, 200, fleet)
		return nil
	case "/api/jobs":
		sendJSON(w, 200, s.listJobs(ws, r.URL.Query().Get("latest") == "1"))
		return nil
	}
	if m := jobPath.FindStringSubmatch(r.URL.Path); m != nil {
		s.mu.Lock()
		j, ok := s.jobs[m[1]]
		s.mu.Unlock()
		if !ok || j["workspace"] != ws {
			sendError(w, 404, "no such job")
			return nil
		}
		sendJSON(w, 200, s.publicJob(j))
		return nil
	}
	if m := reportPath.FindStringSubmatch(r.URL.Path); m != nil {
		if report := s.store.CurrentReport(ws, m[1]); report != nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(report)
			return nil
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(404)
		_, _ = w.Write([]byte("report not generated yet"))
		return nil
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(404)
	_, _ = w.Write([]byte("not found"))
	return nil
}

func (s *Server) listJobs(ws string, latest bool) []map[string]any {
	s.mu.Lock()
	s.pruneJobsLocked()
	var visible []job
	for _, j := range s.jobs {
		if j["workspace"] == ws && (latest || j["state"] == "queued" || j["state"] == "running") {
			visible = append(visible, j)
		}
	}
	s.mu.Unlock()
	if latest {
		// Recover a just-finished run after a refresh, but never one for
		// superseded evidence or context.
		targets, _ := s.store.Load(ws)
		current := map[string]Target{}
		for _, t := range targets {
			current[strOf(t["id"])] = t
		}
		sort.Slice(visible, func(a, b int) bool {
			fa, _ := visible[a]["created_at"].(float64)
			fb, _ := visible[b]["created_at"].(float64)
			return fa < fb
		})
		byTarget := map[string]job{}
		var order []string
		for _, j := range visible {
			t, ok := current[strOf(j["target_id"])]
			if ok && j["input_revision"] == intOf(t["input_revision"]) && j["source_sha256"] == strOf(t["source_sha256"]) {
				if _, seen := byTarget[strOf(j["target_id"])]; !seen {
					order = append(order, strOf(j["target_id"]))
				}
				byTarget[strOf(j["target_id"])] = j
			}
		}
		visible = nil
		for _, id := range order {
			visible = append(visible, byTarget[id])
		}
	}
	out := []map[string]any{}
	for _, j := range visible {
		out = append(out, s.publicJob(j))
	}
	return out
}

var contextKeys = []string{"criticality", "internet_exposed", "reachable", "runtime_observed", "system_exposure",
	"mission_impact", "safety_impact", "context_sources", "publicly_exposed", "bod2604_applicability"}

func (s *Server) post(w http.ResponseWriter, r *http.Request, ws string) error {
	switch r.URL.Path {
	case "/api/demo":
		if _, err := s.readJSON(r); err != nil {
			return err
		}
		target, created, err := CreateDemoTarget(s.store, ws, s.limits.targets, s.limits.sessionSourceBytes)
		switch {
		case errors.Is(err, ErrTargetLimit):
			return badRequest(429, err.Error())
		case errors.Is(err, ErrSourceQuota):
			return badRequest(413, err.Error())
		case err != nil:
			return err
		}
		status := 200
		if created {
			status = 201
		}
		sendJSON(w, status, publicTarget(target))
		return nil
	case "/api/targets":
		body, err := s.readJSON(r)
		if err != nil {
			return err
		}
		if name, _ := body["name"].(string); name == "" {
			return badRequest(400, "name is required")
		}
		fields := map[string]any{}
		for _, key := range append([]string{"name", "url"}, contextKeys...) {
			if v, ok := body[key]; ok {
				fields[key] = v
			}
		}
		target, err := s.store.Add(ws, fields, s.limits.targets)
		switch {
		case errors.Is(err, ErrTargetLimit):
			return badRequest(429, err.Error())
		case err != nil:
			return badRequest(400, err.Error())
		}
		sendJSON(w, 201, publicTarget(target))
		return nil
	case "/api/fleet/import":
		return s.fleetImport(w, r, ws)
	}
	m := targetPath.FindStringSubmatch(r.URL.Path)
	if m == nil || m[2] == "" {
		return badRequest(404, "not found")
	}
	target, err := s.store.Get(ws, m[1])
	if err != nil {
		return badRequest(404, "no such target")
	}
	switch m[2] {
	case "context":
		body, err := s.readJSON(r)
		if err != nil {
			return err
		}
		fields := map[string]any{}
		for _, key := range contextKeys {
			if v, ok := body[key]; ok {
				fields[key] = v
			}
		}
		updated, err := s.store.UpdateInputs(ws, m[1], fields, false)
		if err != nil {
			return badRequest(400, err.Error())
		}
		sendJSON(w, 200, publicTarget(updated))
	case "ssvc-inputs":
		return s.ssvcInputs(w, r, ws, target)
	case "source":
		return s.source(w, r, ws, m[1])
	case "repository":
		return s.repositoryImport(w, r, ws, m[1])
	case "runs":
		if strOf(target["source_file"]) == "" {
			return badRequest(400, "no scan, SBOM, or repository evidence attached")
		}
		body, err := s.readJSON(r)
		if err != nil {
			return err
		}
		if backend := fmt.Sprint(orDefault(body["backend"], "rules")); backend != "rules" {
			return badRequest(400, "backend is not available")
		}
		j, err := s.startJob(ws, target)
		if err != nil {
			return err
		}
		sendJSON(w, 202, s.publicJob(j))
	case "run":
		if publicMode() {
			return badRequest(410, "synchronous runs are disabled in public mode; use /runs and poll the returned job")
		}
		body, err := s.readJSON(r)
		if err != nil {
			return err
		}
		if backend := fmt.Sprint(orDefault(body["backend"], "rules")); backend != "rules" {
			return badRequest(400, "backend is not available")
		}
		select {
		case s.runSlots <- struct{}{}:
		default:
			return badRequest(429, "assessment capacity is busy; retry later")
		}
		defer func() { <-s.runSlots }()
		lock := s.runLock(ws, m[1])
		lock.Lock()
		summary, err := s.runner.Run(r.Context(), ws, target)
		lock.Unlock()
		if err != nil {
			return badRequest(400, exceptionMessage(err))
		}
		sendJSON(w, 200, summary)
	}
	return nil
}

func orDefault(v any, fallback string) any {
	if v == nil {
		return fallback
	}
	return v
}

func (s *Server) ssvcInputs(w http.ResponseWriter, r *http.Request, ws string, target Target) error {
	body, err := s.readJSON(r)
	if err != nil {
		return err
	}
	inputs, ok := body["inputs"].([]any)
	if !ok || len(inputs) > 1000 {
		return badRequest(400, "inputs must be a list of at most 1000 items")
	}
	overrides := map[string]any{}
	if existing, ok := target["ssvc_overrides"].(map[string]any); ok {
		overrides = copyMap(existing)
	}
	for _, raw := range inputs {
		item, ok := raw.(map[string]any)
		if !ok {
			return badRequest(400, "invalid SSVC input")
		}
		key := fmt.Sprint(orDefault(item["finding_key"], ""))
		if key == "" || len(key) > 512 {
			return badRequest(400, "invalid finding key")
		}
		values := map[string]any{}
		if e := orDefault(item["exploitation"], "auto"); e != "auto" {
			if e != "none" && e != "public_poc" && e != "active" {
				return badRequest(400, "invalid Exploitation value")
			}
			values["exploitation"] = e
		}
		if a := orDefault(item["automatable"], "auto"); a != "auto" {
			if a != "no" && a != "yes" {
				return badRequest(400, "invalid Automatable value")
			}
			values["automatable"] = a
		}
		if len(values) > 0 {
			overrides[key] = values
		} else {
			delete(overrides, key)
		}
	}
	if _, err := s.store.UpdateInputs(ws, strOf(target["id"]), map[string]any{"ssvc_overrides": overrides}, false); err != nil {
		return err
	}
	sendJSON(w, 200, map[string]any{"ok": true, "overrides": len(overrides)})
	return nil
}

func (s *Server) source(w http.ResponseWriter, r *http.Request, ws, id string) error {
	body, err := s.readJSON(r)
	if err != nil {
		return err
	}
	content, isText := body["content"].(string)
	if body["content"] == nil || content == "" && isText {
		return badRequest(400, "empty file")
	}
	if !isText {
		return badRequest(400, "content must be text")
	}
	size := int64(len(content))
	if size > s.limits.sourceBytes {
		return badRequest(413, fmt.Sprintf("evidence exceeds the %d byte limit", s.limits.sourceBytes))
	}
	format := detectFormat(content)
	if format == "" {
		return badRequest(400, "unrecognized file — expected Trivy/Grype/OSV JSON or a CycloneDX/SPDX SBOM")
	}
	filename := fmt.Sprint(orDefault(body["filename"], "evidence.json"))
	if filename == "" {
		filename = "evidence.json"
	}
	filename = string([]rune(filename)[:min(255, len([]rune(filename)))])
	sbom := format == "spdx" || format == "cyclonedx"
	status, reason := "provider_reported", "Scanner result consumed as supplied; PatchTriage cannot verify the scanner invocation's scope"
	if sbom {
		status, reason = "unknown", "SBOM component query coverage is evaluated during the run"
	}
	err = s.store.SaveSource(ws, id, content, Source{Format: format, Filename: filename, Kind: "upload",
		Provenance: map[string]any{"provider": "upload", "filename": filename, "coverage_status": "provider_reported",
			"coverage": map[string]any{"status": status, "reason": reason}}}, s.limits.sessionSourceBytes)
	switch {
	case errors.Is(err, ErrSourceQuota):
		return badRequest(413, err.Error())
	case errors.Is(err, ErrNoTarget):
		return badRequest(404, "no such target")
	case err != nil:
		return err
	}
	target, _ := s.store.Get(ws, id)
	sendJSON(w, 200, map[string]any{"ok": true, "format": format, "filename": filename,
		"sha256": strOf(target["source_sha256"]), "size": size})
	return nil
}

func (s *Server) fleetImport(w http.ResponseWriter, r *http.Request, ws string) error {
	body, err := s.readJSON(r)
	if err != nil {
		return err
	}
	ownerURL, _ := body["owner_url"].(string)
	if strings.TrimSpace(ownerURL) == "" {
		return badRequest(400, "owner_url is required")
	}
	limit := s.limits.fleetImportRepos
	if raw := body["limit"]; ingest.Truthy(raw) {
		n, ok := pyInt(raw)
		if !ok {
			return badRequest(400, "limit must be a number")
		}
		limit = n
	}
	limit = max(1, min(limit, s.limits.fleetImportRepos))
	shared := map[string]string{}
	for _, key := range FleetContextFields {
		if v, ok := body[key].(string); ok {
			shared[key] = v
		}
	}
	select {
	case s.importSlots <- struct{}{}:
	default:
		return badRequest(429, "repository import capacity is busy; retry later")
	}
	defer func() { <-s.importSlots }()
	report, err := FleetImport{Store: s.store, GitHub: s.Repository.GitHub, Token: githubImportToken(),
		MaxTargets: s.limits.targets, MaxWorkspaceSourceBytes: s.limits.sessionSourceBytes}.Import(r.Context(), ws,
		ownerURL, limit, ingest.Truthy(body["include_forks"]), ingest.Truthy(body["include_archived"]), shared)
	var repoErr *repository.Error
	if errors.As(err, &repoErr) {
		return badRequest(repoErr.Status, repoErr.Message)
	} else if err != nil {
		return err
	}
	sendJSON(w, 200, report)
	return nil
}

// pyInt is Python's int() for a JSON number or numeric string.
func pyInt(v any) (int, bool) {
	switch x := v.(type) {
	case float64:
		return int(x), true
	case bool:
		if x {
			return 1, true
		}
		return 0, true
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(x))
		return n, err == nil
	}
	return 0, false
}

func (s *Server) repositoryImport(w http.ResponseWriter, r *http.Request, ws, id string) error {
	body, err := s.readJSON(r)
	if err != nil {
		return err
	}
	repositoryURL, _ := body["repository_url"].(string)
	if strings.TrimSpace(repositoryURL) == "" {
		return badRequest(400, "repository_url is required")
	}
	select {
	case s.importSlots <- struct{}{}:
	default:
		return badRequest(429, "repository import capacity is busy; retry later")
	}
	evidence, err := s.Repository.Acquire(r.Context(), repositoryURL, githubImportToken(), s.limits.sourceBytes,
		repository.GenericEnabled())
	<-s.importSlots
	var repoErr *repository.Error
	if errors.As(err, &repoErr) {
		return badRequest(repoErr.Status, repoErr.Message)
	} else if err != nil {
		return err
	}
	size := int64(len(evidence.Content))
	if size > s.limits.sourceBytes {
		return badRequest(413, fmt.Sprintf("repository evidence exceeds the %d byte limit", s.limits.sourceBytes))
	}
	filename := strings.ReplaceAll(strOf(evidence.Provenance["repository"]), "/", "_") + "." + evidence.Format + ".json"
	err = s.store.SaveSource(ws, id, evidence.Content, Source{Format: evidence.Format, Filename: filename,
		Kind: "repository", Provenance: evidence.Provenance}, s.limits.sessionSourceBytes)
	switch {
	case errors.Is(err, ErrSourceQuota):
		return badRequest(413, err.Error())
	case errors.Is(err, ErrNoTarget):
		return badRequest(404, "no such target")
	case err != nil:
		return err
	}
	target, _ := s.store.Get(ws, id)
	sendJSON(w, 200, map[string]any{"ok": true, "format": evidence.Format, "filename": filename,
		"sha256": strOf(target["source_sha256"]), "size": size, "provenance": evidence.Provenance})
	return nil
}

func (s *Server) delete(w http.ResponseWriter, r *http.Request, ws string) error {
	m := targetPath.FindStringSubmatch(r.URL.Path)
	if m == nil || m[2] != "" {
		return badRequest(404, "not found")
	}
	s.mu.Lock()
	for _, j := range s.jobs {
		if j["workspace"] == ws && j["target_id"] == m[1] && (j["state"] == "queued" || j["state"] == "running") {
			s.mu.Unlock()
			return badRequest(409, "target has an active assessment")
		}
	}
	s.mu.Unlock()
	if ok, err := s.store.Delete(ws, m[1]); err != nil || !ok {
		return badRequest(404, "no such target")
	}
	s.runLocks.Delete(ws + "|" + m[1])
	w.WriteHeader(204)
	return nil
}

// ------------------------------------------------------------ serve

func openBrowser(target string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", target)
	case "darwin":
		cmd = exec.Command("open", target)
	default:
		cmd = exec.Command("xdg-open", target)
	}
	_ = cmd.Start()
}

// Serve runs the GUI until ctx is cancelled.
func Serve(ctx context.Context, host string, port int, open bool, runner *Runner) error {
	server := NewServer(runner.Store, runner)
	address := net.JoinHostPort(host, strconv.Itoa(port))
	httpServer := &http.Server{Addr: address, Handler: server, ReadHeaderTimeout: 10 * time.Second}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	link := "http://" + address + "/"
	fmt.Printf("PatchTriage console: %s  (Ctrl-C to stop)\n", link)
	if open {
		time.AfterFunc(600*time.Millisecond, func() { openBrowser(link) })
	}
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = httpServer.Shutdown(shutdown)
				return
			case <-ticker.C:
				server.cleanupExpired()
			}
		}
	}()
	if err := httpServer.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
