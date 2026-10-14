package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/d01ki/PatchTriage-go/internal/ai"
	"github.com/d01ki/PatchTriage-go/internal/decision"
	"github.com/d01ki/PatchTriage-go/internal/model"
)

// goldenFindings decodes the findings of a Python golden report.
func goldenFindings(t *testing.T, name string) []*model.Finding {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/golden/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var report struct{ Findings []map[string]any }
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	var out []*model.Finding
	for _, f := range report.Findings {
		delete(f, "triage")
		delete(f, "detected_at")
		delete(f, "first_seen")
		f["enrichment"].(map[string]any)["enriched_at"] = nil
		encoded, _ := json.Marshal(f)
		var finding model.Finding
		if err := json.Unmarshal(encoded, &finding); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out = append(out, &finding)
	}
	return out
}

// TestAIMergeAndAuditMatchPython replays testdata/ai_audit_python.json:
// Python's _merge_ai_recommendation + audit_finding over golden findings.
func TestAIMergeAndAuditMatchPython(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/ai_audit_python.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Golden           string                 `json:"golden"`
		Index            int                    `json:"index"`
		Recommendation   map[string]any         `json:"recommendation"`
		Rationale        string                 `json:"rationale"`
		AIRecommendation model.AIRecommendation `json:"ai_recommendation"`
		Flags            []string               `json:"flags"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	findings := map[string][]*model.Finding{}
	for _, c := range cases {
		if findings[c.Golden] == nil {
			findings[c.Golden] = goldenFindings(t, c.Golden)
		}
		f := findings[c.Golden][c.Index]
		r, err := validateRecommendation(c.Recommendation)
		if err != nil {
			t.Fatalf("%s[%d]: %v", c.Golden, c.Index, err)
		}
		f.Triage = mergeRecommendation(f, r, "test:model")
		flags := AuditFinding(f)["flags"].([]string)
		if f.Triage.Rationale != c.Rationale || !reflect.DeepEqual(*f.Triage.AIRecommendation, c.AIRecommendation) ||
			strings.Join(flags, "|") != strings.Join(c.Flags, "|") {
			t.Errorf("%s[%d] %v:\n got  %q %+v %v\n want %q %+v %v", c.Golden, c.Index, c.Recommendation,
				f.Triage.Rationale, *f.Triage.AIRecommendation, flags, c.Rationale, c.AIRecommendation, c.Flags)
		}
	}
}

// fakeBackend returns a copy of result (or fails) and counts calls.
type fakeBackend struct {
	result *model.Triage
	fail   bool
	calls  int32
}

func (b *fakeBackend) Triage(context.Context, *model.Finding) (*model.Triage, error) {
	atomic.AddInt32(&b.calls, 1)
	if b.fail {
		return nil, errors.New("simulated API failure")
	}
	copied := *b.result
	return &copied, nil
}

func quietAndKEV(t *testing.T) (quiet, kev *model.Finding) {
	findings := triagedFindings(t)
	kev = libc(findings)
	kev.Asset.InternetExposed = boolPtr(true)
	kev.Asset.Criticality, kev.Asset.SystemExposure, kev.Asset.Automatable = "critical", "open", "yes"
	kev.Asset.MissionImpact, kev.Asset.SafetyImpact = "mef_failure", "critical"
	kev.Enrichment = model.Enrichment{InCISAKEV: true, KEVRansomware: true, EPSSScore: f64(0.856), NVDCVSSScore: f64(7.8)}
	quiet = find(findings, func(f *model.Finding) bool { return f.Package.Name == "lodash" })
	quiet.Asset.InternetExposed = boolPtr(false)
	quiet.Asset.Criticality, quiet.Asset.SystemExposure, quiet.Asset.Automatable = "low", "small", "no"
	quiet.Asset.MissionImpact, quiet.Asset.SafetyImpact = "degraded", "negligible"
	quiet.Enrichment = model.Enrichment{EPSSScore: f64(0.018), NVDCVSSScore: f64(7.2), EnrichedAt: timePtrNow()}
	return quiet, kev
}

func TestCascadeRouting(t *testing.T) {
	quiet, kev := quietAndKEV(t)
	ctx := context.Background()

	baseline := decision.Triage(kev)
	deepResult := *baseline
	deepResult.Rationale = "actively exploited"
	deep := &fakeBackend{result: &deepResult}
	out, err := (&CascadeBackend{Screen: &fakeBackend{result: baseline}, Deep: deep}).Triage(ctx, kev)
	if err != nil || deep.calls != 1 || out.Escalated == nil || !*out.Escalated ||
		!contains(out.EscalationReasons, "ssvc_immediate") || out.Rationale != "actively exploited" {
		t.Errorf("KEV escalation = %+v, %v", out, err)
	}

	baseline = decision.Triage(quiet)
	deep = &fakeBackend{result: baseline}
	out, _ = (&CascadeBackend{Screen: &fakeBackend{result: baseline}, Deep: deep}).Triage(ctx, quiet)
	if deep.calls != 0 || out.Escalated == nil || *out.Escalated {
		t.Errorf("clean finding escalated: %+v", out)
	}

	flagged := *baseline
	flagged.Rationale = "EPSS of 0.99 is unlikely"
	deep = &fakeBackend{result: baseline}
	out, _ = (&CascadeBackend{Screen: &fakeBackend{result: &flagged}, Deep: deep}).Triage(ctx, quiet)
	if deep.calls != 1 || !strings.HasPrefix(strings.Join(out.EscalationReasons, " "), "audit_flags:") {
		t.Errorf("audit-flagged result not escalated: %+v", out)
	}
}

func TestRunTriageFallsBackAndPreservesOrder(t *testing.T) {
	findings := triagedFindings(t)
	if err := RunTriage(context.Background(), findings, &fakeBackend{fail: true}, 1, nil); err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Triage.Backend != "rules_fallback" || !strings.Contains(f.Triage.Error, "simulated API failure") ||
			decision.PriorityRank(f.Triage.Priority) < 0 {
			t.Errorf("fallback = %+v", f.Triage)
		}
	}
	ok := &fakeBackend{result: &model.Triage{Priority: "P2", Action: "patch_scheduled", Rationale: "x", SuggestedDeadlineDays: 14}}
	_ = RunTriage(context.Background(), findings, ok, 4, nil)
	if int(ok.calls) != len(findings) {
		t.Errorf("calls = %d", ok.calls)
	}
	for _, f := range findings {
		if f.Triage.Priority != "P2" {
			t.Errorf("parallel result lost: %+v", f.Triage)
		}
	}
	_ = RunTriage(context.Background(), findings, RulesBackend{}, 4, nil)
	for _, f := range findings {
		if f.Triage.Backend != "ssvc" {
			t.Errorf("rules backend = %q", f.Triage.Backend)
		}
	}
}

// fakeProvider records calls and returns result.
type fakeProvider struct {
	result map[string]any
	calls  []string
}

func (p *fakeProvider) Name() string { return "test-provider" }

func (p *fakeProvider) Complete(_ context.Context, _, systemPrompt, payload string, _ ai.Tool) (map[string]any, error) {
	p.calls = append(p.calls, systemPrompt+"\x00"+payload)
	copied := map[string]any{}
	for k, v := range p.result {
		copied[k] = v
	}
	return copied, nil
}

func TestAIBackendKeepsSSVCAuthoritative(t *testing.T) {
	quiet, _ := quietAndKEV(t)
	baseline := decision.Triage(quiet)
	provider := &fakeProvider{result: map[string]any{"action": baseline.Action, "rationale": "Explain the supplied SSVC path.",
		"remediation_steps": []any{"Review the vendor advisory."}, "uncertainties": []any{}}}
	result, err := (&AIBackend{Provider: provider, Model: "example-model"}).Triage(context.Background(), quiet)
	if err != nil {
		t.Fatal(err)
	}
	if result.Priority != baseline.Priority || result.Action != baseline.Action ||
		result.SuggestedDeadlineDays != baseline.SuggestedDeadlineDays || result.Backend != "test-provider:example-model" ||
		strings.Join(result.AIRecommendation.RemediationSteps, ",") != "Review the vendor advisory." {
		t.Errorf("result = %+v", result)
	}
	if call := provider.calls[0]; !strings.HasPrefix(call, TriageSystemPrompt+"\x00") || !strings.Contains(call, `"ssvc_assessment"`) ||
		strings.Contains(call, `"triage"`) {
		t.Errorf("call = %.300s", call)
	}

	provider.result = map[string]any{"action": "invent_a_priority", "rationale": "invalid", "remediation_steps": []any{},
		"uncertainties": []any{}}
	_ = RunTriage(context.Background(), []*model.Finding{quiet}, &AIBackend{Provider: provider, Model: "m"}, 1, nil)
	if quiet.Triage.Backend != "rules_fallback" || !strings.Contains(quiet.Triage.Error, "invalid action") {
		t.Errorf("invalid output = %+v", quiet.Triage)
	}
}

func TestAuditFlagsPatchInstructionWithoutFix(t *testing.T) {
	quiet, _ := quietAndKEV(t)
	quiet.Package.FixedVersion = ""
	r, _ := validateRecommendation(map[string]any{"action": decision.Triage(quiet).Action, "rationale": "No fix yet.",
		"remediation_steps": []any{"Upgrade the package when possible"}, "uncertainties": []any{}})
	quiet.Triage = mergeRecommendation(quiet, r, "test:model")
	if !hasFlag(AuditFinding(quiet), "ai_patch_instruction_without_fix") {
		t.Errorf("flags = %v", AuditFinding(quiet)["flags"])
	}
}

func TestOpenAICompatibleProviderUsesStructuredToolCall(t *testing.T) {
	arguments := `{"action": "monitor", "rationale": "The supplied SSVC path is Defer.", "remediation_steps": ["Continue monitoring."], "uncertainties": []}`
	var request map[string]any
	var auth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &request)
		if r.URL.Path != "/v1/chat/completions" {
			http.NotFound(w, r)
			return
		}
		quoted, _ := json.Marshal(arguments)
		_, _ = w.Write([]byte(`{"choices": [{"message": {"tool_calls": [{"function": {"name": "triage", "arguments": ` + string(quoted) + `}}]}}]}`))
	}))
	defer server.Close()
	t.Setenv("PATCHTRIAGE_AI_API_KEY", "")
	t.Setenv("OPENAI_API_KEY", "")
	provider, err := ai.NewOpenAICompatible(server.URL+"/v1", "")
	if err != nil {
		t.Fatal(err)
	}
	result, err := provider.Complete(context.Background(), "local-model", TriageSystemPrompt, "{}", TriageTool)
	if err != nil || result["action"] != "monitor" || len(result) != 4 {
		t.Fatalf("result = %v, %v", result, err)
	}
	tools := request["tools"].([]any)[0].(map[string]any)["function"].(map[string]any)
	if request["tool_choice"].(map[string]any)["function"].(map[string]any)["name"] != "triage" || tools["strict"] != true || auth != "" {
		t.Errorf("request = %v auth %q", request, auth)
	}
}

func TestAnthropicProviderForcesCachedToolCall(t *testing.T) {
	var request map[string]any
	var headers http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers = r.Header
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &request)
		_, _ = w.Write([]byte(`{"content": [{"type": "text", "text": "hi"}, {"type": "tool_use", "name": "triage",
			"input": {"action": "monitor", "rationale": "r", "remediation_steps": [], "uncertainties": []}}]}`))
	}))
	defer server.Close()
	t.Setenv("ANTHROPIC_API_KEY", "test-key")
	t.Setenv("ANTHROPIC_BASE_URL", server.URL)
	provider, err := ai.NewAnthropic()
	if err != nil {
		t.Fatal(err)
	}
	result, err := provider.Complete(context.Background(), "claude-test", TriageSystemPrompt, "{}", TriageTool)
	if err != nil || result["action"] != "monitor" {
		t.Fatalf("result = %v, %v", result, err)
	}
	system := request["system"].([]any)[0].(map[string]any)
	if headers.Get("x-api-key") != "test-key" || headers.Get("anthropic-version") != "2023-06-01" ||
		request["model"] != "claude-test" || request["max_tokens"] != 1024.0 || system["text"] != TriageSystemPrompt ||
		system["cache_control"].(map[string]any)["type"] != "ephemeral" ||
		request["tool_choice"].(map[string]any)["name"] != "triage" {
		t.Errorf("request = %v", request)
	}
}

func boolPtr(v bool) *bool { return &v }

func timePtrNow() *time.Time {
	now := time.Now().UTC()
	return &now
}

func TestRunTriageBatchKeysResultsByCustomID(t *testing.T) {
	findings := triagedFindings(t)[:2]
	action := decision.Triage(findings[1]).Action
	var polled int32
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/messages/batches":
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), `"custom_id":"finding-1"`) {
				t.Errorf("batch body = %.200s", body)
			}
			_, _ = w.Write([]byte(`{"id": "b1", "processing_status": "in_progress", "request_counts": {"processing": 2}}`))
		case r.URL.Path == "/v1/messages/batches/b1":
			atomic.AddInt32(&polled, 1)
			_, _ = w.Write([]byte(`{"id": "b1", "processing_status": "ended", "results_url": "` + server.URL + `/results"}`))
		case r.URL.Path == "/results":
			// finding-0 errored; finding-1 succeeded (results arrive out of order).
			_, _ = w.Write([]byte(`{"custom_id": "finding-1", "result": {"type": "succeeded", "message": {"content": [{"type": "tool_use", "name": "triage", "input": {"action": "` + action + `", "rationale": "batched", "remediation_steps": [], "uncertainties": []}}]}}}
{"custom_id": "finding-0", "result": {"type": "errored"}}
`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	t.Setenv("PATCHTRIAGE_AI_PROVIDER", "")
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("PATCHTRIAGE_AI_API_KEY", "")
	t.Setenv("PATCHTRIAGE_AI_BASE_URL", "")
	t.Setenv("ANTHROPIC_API_KEY", "test-key")
	t.Setenv("ANTHROPIC_BASE_URL", server.URL)
	if err := RunTriageBatch(context.Background(), findings, "claude-test", "", time.Millisecond, func(string) {}); err != nil {
		t.Fatal(err)
	}
	if findings[0].Triage.Backend != "rules_fallback" || findings[0].Triage.Error != "batch entry errored or expired" ||
		findings[1].Triage.Backend != "anthropic:claude-test (batch)" || findings[1].Triage.Rationale != "batched" || polled != 1 {
		t.Errorf("batch triage = %+v / %+v (polled %d)", findings[0].Triage, findings[1].Triage, polled)
	}
	if err := RunTriageBatch(context.Background(), findings, "", "ollama", time.Millisecond, func(string) {}); err == nil ||
		!strings.Contains(err.Error(), "requires the Anthropic provider") {
		t.Errorf("non-Anthropic batch err = %v", err)
	}
}
