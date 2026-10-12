// Package web serves the PatchTriage GUI: a target registry, asynchronous
// assessment jobs and the single-page console from the Python version.
package web

// The target registry. A target is one system to keep patched, with its
// SSVC context, BOD 26-04 inputs, supplemental evidence and an attached scan
// or SBOM. Everything is JSON under the config directory; each anonymous
// browser workspace has its own directory so visitors never share data.
// Changing evidence or context bumps input_revision and invalidates derived
// summaries and reports.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/d01ki/PatchTriage-go/internal/model"
)

// Target is one registry record, kept as the JSON object the GUI uses.
type Target = map[string]any

var (
	ErrStaleInput  = errors.New("target evidence or context changed while assessment was running; the stale result was discarded")
	ErrTargetLimit = errors.New("target limit reached")
	ErrSourceQuota = errors.New("anonymous workspace evidence quota exceeded")
	ErrNoTarget    = errors.New("no such target")
)

var (
	targetIDPattern    = regexp.MustCompile(`^[0-9a-f]{12}$`)
	workspaceIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
	sourceFilePattern  = regexp.MustCompile(`^[0-9a-f]{12}_source(?:_[0-9a-f]{64})?\.json$`)
	criticalities      = map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "unknown": true}
	contextFields      = []string{"system_exposure", "automatable", "mission_impact", "safety_impact", "publicly_exposed", "bod2604_applicability"}
)

// DefaultConfigDir honors PATCHTRIAGE_CONFIG_DIR, else ~/.config/patchtriage-go.
func DefaultConfigDir() string {
	if dir := os.Getenv("PATCHTRIAGE_CONFIG_DIR"); dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "patchtriage-go-config")
	}
	return filepath.Join(home, ".config", "patchtriage-go")
}

// Store persists targets, evidence and run artifacts under Root.
type Store struct {
	Root string
	mu   sync.Mutex
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func intOf(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case float64:
		return int(x)
	}
	return 0
}

func strOf(v any) string {
	s, _ := v.(string)
	return s
}

func validTargetID(id string) error {
	if !targetIDPattern.MatchString(id) {
		return errors.New("invalid target id")
	}
	return nil
}

// dir is the private target directory of one workspace ("" = local store).
func (s *Store) dir(ws string) (string, error) {
	d := filepath.Join(s.Root, "targets")
	if ws != "" {
		if !workspaceIDPattern.MatchString(ws) {
			return "", errors.New("invalid workspace id")
		}
		d = filepath.Join(s.Root, "sessions", ws, "targets")
	}
	return d, os.MkdirAll(d, 0o700)
}

// Touch records workspace activity for retention.
func (s *Store) Touch(ws string) {
	if !workspaceIDPattern.MatchString(ws) {
		return
	}
	d := filepath.Join(s.Root, "sessions", ws)
	if os.MkdirAll(d, 0o700) == nil {
		now := time.Now()
		_ = os.Chtimes(d, now, now)
	}
}

func writeAtomic(path string, content []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, content, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func (s *Store) load(ws string) ([]Target, error) {
	d, err := s.dir(ws)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(filepath.Join(d, "targets.json"))
	var targets []Target
	if err != nil || json.Unmarshal(raw, &targets) != nil {
		return []Target{}, nil
	}
	return targets, nil
}

func (s *Store) save(ws string, targets []Target) error {
	d, err := s.dir(ws)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(targets, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(d, "targets.json"), raw)
}

// Load lists a workspace's targets.
func (s *Store) Load(ws string) ([]Target, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.load(ws)
}

func find(targets []Target, id string) int {
	for i, t := range targets {
		if t["id"] == id {
			return i
		}
	}
	return -1
}

// Get returns one target or ErrNoTarget.
func (s *Store) Get(ws, id string) (Target, error) {
	if err := validTargetID(id); err != nil {
		return nil, err
	}
	targets, err := s.Load(ws)
	if err != nil {
		return nil, err
	}
	if i := find(targets, id); i >= 0 {
		return targets[i], nil
	}
	return nil, ErrNoTarget
}

func cleanName(v any) (string, error) {
	name := strings.TrimSpace(fmt.Sprint(orEmpty(v)))
	if name == "" {
		return "", errors.New("name is required")
	}
	if len([]rune(name)) > 120 {
		return "", errors.New("name must be 120 characters or fewer")
	}
	return name, nil
}

func orEmpty(v any) any {
	if v == nil {
		return ""
	}
	return v
}

func cleanURL(v any) (string, error) {
	raw := strings.TrimSpace(fmt.Sprint(orEmpty(v)))
	if raw == "" {
		return "", nil
	}
	if len(raw) > 2048 {
		return "", errors.New("url is too long")
	}
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return "", errors.New("url must be an absolute http:// or https:// URL")
	}
	if parsed.User != nil {
		return "", errors.New("url must not contain embedded credentials")
	}
	return raw, nil
}

func cleanContext(field string, v any) (string, error) {
	if b, ok := v.(bool); ok && field == "automatable" {
		if b {
			return "yes", nil
		}
		return "no", nil
	}
	text := ""
	if v != nil && v != false {
		text = fmt.Sprint(v)
	}
	return model.NormalizeChoice(field, text)
}

func cleanSources(v any) ([]string, error) {
	var items []any
	switch x := v.(type) {
	case nil:
		return []string{}, nil
	case string:
		items = []any{x}
	case []any:
		items = x
	case []string:
		for _, s := range x {
			items = append(items, s)
		}
	default:
		return nil, errors.New("context_sources must be a list")
	}
	out := []string{}
	for _, item := range items[:min(10, len(items))] {
		if s := strings.TrimSpace(fmt.Sprint(item)); s != "" {
			out = append(out, string([]rune(s)[:min(80, len([]rune(s)))]))
		}
	}
	return out, nil
}

// applyFields validates and applies fields to a target record.
func applyFields(t Target, fields map[string]any) error {
	if v, ok := fields["name"]; ok && v != nil {
		name, err := cleanName(v)
		if err != nil {
			return err
		}
		t["name"] = name
	}
	if v, ok := fields["url"]; ok && v != nil {
		u, err := cleanURL(v)
		if err != nil {
			return err
		}
		t["url"] = u
	}
	if v, ok := fields["criticality"]; ok && v != nil {
		c := strings.ToLower(strings.TrimSpace(fmt.Sprint(v)))
		if c == "" {
			c = "unknown"
		}
		if !criticalities[c] {
			return errors.New("criticality must be critical, high, medium, low, or unknown")
		}
		t["criticality"] = c
	}
	for _, key := range []string{"internet_exposed", "reachable", "runtime_observed"} {
		if v, ok := fields[key]; ok {
			if _, isBool := v.(bool); v != nil && !isBool {
				return fmt.Errorf("%s must be true or false", key)
			}
			t[key] = v
		}
	}
	for _, key := range contextFields {
		if v, ok := fields[key]; ok && v != nil {
			value, err := cleanContext(key, v)
			if err != nil {
				return err
			}
			t[key] = value
		}
	}
	if v, ok := fields["context_sources"]; ok && v != nil {
		sources, err := cleanSources(v)
		if err != nil {
			return err
		}
		t["context_sources"] = sources
	}
	for _, key := range []string{"source_file", "source_format", "source_name", "source_sha256", "source_kind"} {
		if v, ok := fields[key]; ok && v != nil {
			t[key] = fmt.Sprint(v)
		}
	}
	if v, ok := fields["source_size"]; ok && v != nil {
		t["source_size"] = max(0, intOf(v))
	}
	if v, ok := fields["source_provenance"]; ok && v != nil {
		provenance, isMap := v.(map[string]any)
		if !isMap {
			return errors.New("source_provenance must be an object")
		}
		t["source_provenance"] = provenance
	}
	if v, ok := fields["input_revision"]; ok && v != nil {
		t["input_revision"] = max(0, intOf(v))
	}
	if v, ok := fields["ssvc_overrides"]; ok && v != nil {
		overrides, isMap := v.(map[string]any)
		if !isMap || len(overrides) > 1000 {
			return errors.New("ssvc_overrides must be an object")
		}
		t["ssvc_overrides"] = overrides
	}
	return nil
}

// Add registers a target. maxTargets <= 0 means unlimited.
func (s *Store) Add(ws string, fields map[string]any, maxTargets int) (Target, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	targets, err := s.load(ws)
	if err != nil {
		return nil, err
	}
	if maxTargets > 0 && len(targets) >= maxTargets {
		return nil, fmt.Errorf("%w (%d)", ErrTargetLimit, maxTargets)
	}
	target := Target{
		"id": randomHex(6), "name": "", "url": "", "criticality": "unknown",
		"internet_exposed": nil, "reachable": nil, "runtime_observed": nil,
		"system_exposure": "unknown", "automatable": "unknown", "mission_impact": "unknown",
		"safety_impact": "unknown", "publicly_exposed": "unknown", "bod2604_applicability": "unknown",
		"context_sources": []string{}, "ssvc_overrides": map[string]any{}, "demo": fields["demo"] == true,
		"source_file": "", "source_format": "", "source_name": "", "source_sha256": "", "source_size": 0,
		"source_kind": "", "source_provenance": map[string]any{}, "input_revision": 0,
		"created_at": float64(time.Now().UnixNano()) / 1e9,
	}
	if _, ok := fields["name"]; !ok {
		return nil, errors.New("name is required")
	}
	if err := applyFields(target, fields); err != nil {
		return nil, err
	}
	targets = append(targets, target)
	return target, s.save(ws, targets)
}

func (s *Store) invalidate(ws, id string) {
	d, err := s.dir(ws)
	if err != nil {
		return
	}
	// The summary is the commit manifest: remove it first.
	_ = os.Remove(filepath.Join(d, id+"_summary.json"))
	_ = os.Remove(filepath.Join(d, id+"_report.html"))
	reports, _ := filepath.Glob(filepath.Join(d, id+"_report_*.html"))
	for _, r := range reports {
		_ = os.Remove(r)
	}
}

func (s *Store) updateInputs(ws, id string, fields map[string]any, clearOverrides bool) (Target, error) {
	targets, err := s.load(ws)
	if err != nil {
		return nil, err
	}
	i := find(targets, id)
	if i < 0 {
		return nil, ErrNoTarget
	}
	candidate := Target{}
	for k, v := range targets[i] {
		candidate[k] = v
	}
	updates := map[string]any{}
	for k, v := range fields {
		updates[k] = v
	}
	if clearOverrides {
		updates["ssvc_overrides"] = map[string]any{}
	}
	updates["input_revision"] = intOf(targets[i]["input_revision"]) + 1
	if err := applyFields(candidate, updates); err != nil {
		return nil, err
	}
	s.invalidate(ws, id)
	targets[i] = candidate
	return candidate, s.save(ws, targets)
}

// UpdateInputs commits changed decision inputs with a new revision and
// invalidates derived results. Validation happens before invalidation.
func (s *Store) UpdateInputs(ws, id string, fields map[string]any, clearOverrides bool) (Target, error) {
	if err := validTargetID(id); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.updateInputs(ws, id, fields, clearOverrides)
}

// Delete removes a target with its evidence and results.
func (s *Store) Delete(ws, id string) (bool, error) {
	if err := validTargetID(id); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	targets, err := s.load(ws)
	if err != nil {
		return false, err
	}
	i := find(targets, id)
	if i < 0 {
		return false, nil
	}
	d, _ := s.dir(ws)
	s.invalidate(ws, id)
	sources, _ := filepath.Glob(filepath.Join(d, id+"_source*.json"))
	for _, src := range sources {
		_ = os.Remove(src)
	}
	return true, s.save(ws, append(targets[:i], targets[i+1:]...))
}

// Source describes uploaded evidence.
type Source struct {
	Format, Filename, Kind string
	Provenance             map[string]any
	Updates                map[string]any // extra target fields committed with the source
}

func sourceUsage(d string) int64 {
	var total int64
	matches, _ := filepath.Glob(filepath.Join(d, "*_source*.json"))
	for _, m := range matches {
		if sourceFilePattern.MatchString(filepath.Base(m)) {
			if info, err := os.Lstat(m); err == nil {
				total += info.Size()
			}
		}
	}
	return total
}

// SaveSource stores evidence content-addressed and links it to the target,
// clearing analyst overrides and bumping the revision. maxBytes <= 0 means
// no workspace quota.
func (s *Store) SaveSource(ws, id, content string, src Source, maxBytes int64) error {
	if err := validTargetID(id); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	targets, err := s.load(ws)
	if err != nil {
		return err
	}
	i := find(targets, id)
	if i < 0 {
		return ErrNoTarget
	}
	d, err := s.dir(ws)
	if err != nil {
		return err
	}
	encoded := []byte(content)
	if maxBytes > 0 {
		previous := int64(0)
		if old := strOf(targets[i]["source_file"]); old != "" && filepath.Dir(old) == d &&
			sourceFilePattern.MatchString(filepath.Base(old)) && strings.HasPrefix(filepath.Base(old), id+"_source") {
			if info, err := os.Lstat(old); err == nil {
				previous = info.Size()
			}
		}
		if max(0, sourceUsage(d)-previous)+int64(len(encoded)) > maxBytes {
			return ErrSourceQuota
		}
	}
	sum := sha256.Sum256(encoded)
	digest := hex.EncodeToString(sum[:])
	path := filepath.Join(d, id+"_source_"+digest+".json")
	if err := writeAtomic(path, encoded); err != nil {
		return err
	}
	name := src.Filename
	if name == "" {
		name = filepath.Base(path)
	}
	provenance := src.Provenance
	if provenance == nil {
		provenance = map[string]any{}
	}
	updates := map[string]any{}
	for k, v := range src.Updates {
		updates[k] = v
	}
	for k, v := range map[string]any{"source_file": path, "source_format": src.Format,
		"source_name": string([]rune(name)[:min(255, len([]rune(name)))]), "source_sha256": digest,
		"source_size": len(encoded), "source_kind": src.Kind, "source_provenance": provenance} {
		updates[k] = v
	}
	if _, err := s.updateInputs(ws, id, updates, true); err != nil {
		if strOf(targets[i]["source_file"]) != path {
			_ = os.Remove(path)
		}
		return err
	}
	old, _ := filepath.Glob(filepath.Join(d, id+"_source*.json"))
	for _, candidate := range old {
		if candidate != path && sourceFilePattern.MatchString(filepath.Base(candidate)) {
			_ = os.Remove(candidate) // best effort; leftovers still count toward the quota
		}
	}
	return nil
}

func current(t Target, revision int, sha string) bool {
	return intOf(t["input_revision"]) == revision && strOf(t["source_sha256"]) == sha
}

// UpdateProvenanceIfCurrent attaches coverage only when it still describes
// the current evidence and context.
func (s *Store) UpdateProvenanceIfCurrent(ws, id string, provenance map[string]any, revision int, sha string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	targets, err := s.load(ws)
	if err != nil {
		return err
	}
	i := find(targets, id)
	if i < 0 || !current(targets[i], revision, sha) {
		return ErrStaleInput
	}
	targets[i]["source_provenance"] = provenance
	return s.save(ws, targets)
}

// SaveRunArtifacts publishes a run's report and summary, atomically, only
// when the run's inputs are still current. The summary file is the commit.
func (s *Store) SaveRunArtifacts(ws, id string, summary map[string]any, html string, revision int, sha string) error {
	if err := validTargetID(id); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	targets, err := s.load(ws)
	if err != nil {
		return err
	}
	i := find(targets, id)
	if i < 0 || !current(targets[i], revision, sha) {
		return ErrStaleInput
	}
	d, err := s.dir(ws)
	if err != nil {
		return err
	}
	generation := randomHex(8)
	report := filepath.Join(d, id+"_report_"+generation+".html")
	if err := writeAtomic(report, []byte(html)); err != nil {
		return err
	}
	payload := map[string]any{}
	for k, v := range summary {
		payload[k] = v
	}
	payload["input_revision"], payload["source_sha256"] = revision, sha
	payload["assessed_at"] = float64(time.Now().UnixNano()) / 1e9
	payload["run_generation"], payload["report_file"] = generation, filepath.Base(report)
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err == nil {
		err = writeAtomic(filepath.Join(d, id+"_summary.json"), raw)
	}
	if err != nil {
		_ = os.Remove(report)
		return err
	}
	others, _ := filepath.Glob(filepath.Join(d, id+"_report_*.html"))
	for _, o := range append(others, filepath.Join(d, id+"_report.html")) {
		if o != report {
			_ = os.Remove(o) // a viewer may hold an old report open on Windows
		}
	}
	return nil
}

func (s *Store) loadSummary(ws, id string) (map[string]any, string) {
	targets, err := s.load(ws)
	if err != nil || validTargetID(id) != nil {
		return nil, ""
	}
	i := find(targets, id)
	d, _ := s.dir(ws)
	raw, readErr := os.ReadFile(filepath.Join(d, id+"_summary.json"))
	var payload map[string]any
	if i < 0 || readErr != nil || json.Unmarshal(raw, &payload) != nil || payload == nil {
		return nil, ""
	}
	if intOf(payload["input_revision"]) != intOf(targets[i]["input_revision"]) ||
		strOf(payload["source_sha256"]) != strOf(targets[i]["source_sha256"]) {
		return nil, ""
	}
	name := strOf(payload["report_file"])
	if !regexp.MustCompile(`^` + id + `_report_[0-9a-f]{16}\.html$`).MatchString(name) {
		return nil, ""
	}
	report := filepath.Join(d, name)
	if _, err := os.Stat(report); err != nil {
		return nil, ""
	}
	return payload, report
}

// LoadSummary returns the current summary; stale artifacts never return.
func (s *Store) LoadSummary(ws, id string) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	summary, _ := s.loadSummary(ws, id)
	return summary
}

// CurrentReport reads the report committed by the current summary.
func (s *Store) CurrentReport(ws, id string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, path := s.loadSummary(ws, id); path != "" {
		if raw, err := os.ReadFile(path); err == nil {
			return raw
		}
	}
	return nil
}

// Cleanup deletes anonymous workspaces idle longer than maxAge.
func (s *Store) Cleanup(maxAge time.Duration, exclude map[string]bool) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	root := filepath.Join(s.Root, "sessions")
	entries, err := os.ReadDir(root)
	if err != nil {
		return 0
	}
	removed := 0
	for _, e := range entries {
		if !e.IsDir() || !workspaceIDPattern.MatchString(e.Name()) || exclude[e.Name()] {
			continue
		}
		if info, err := e.Info(); err == nil && time.Since(info.ModTime()) > maxAge {
			if os.RemoveAll(filepath.Join(root, e.Name())) == nil {
				removed++
			}
		}
	}
	return removed
}
