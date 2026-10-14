package pipeline

// AI-assisted triage. The deterministic CERT/CC SSVC Deployer tree owns
// action timing; a model receives that final assessment and may add
// explanation, remediation steps and uncertainty notes, but it cannot
// rescore or override the decision. Backends:
//
//	rules    deterministic SSVC (no API key)
//	ai       provider-neutral structured explanation (Anthropic or an
//	         OpenAI-compatible endpoint; "claude" remains an alias)
//	cascade  a fast screening model for every finding; urgent,
//	         low-confidence or audit-flagged results go to a deeper model
//
// A finding whose API call fails keeps the deterministic baseline and is
// tagged rules_fallback, so a network blip never aborts a run.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/d01ki/PatchTriage-go/internal/ai"
	"github.com/d01ki/PatchTriage-go/internal/decision"
	"github.com/d01ki/PatchTriage-go/internal/model"
)

// TriageSystemPrompt is the instruction every provider receives.
const TriageSystemPrompt = `You are a vulnerability-management analyst performing patch triage.
You will receive ONE finding plus a deterministic SSVC Deployer assessment.
The SSVC decision and P1-P4 mapping are final. Your role is to explain that
decision and propose concrete remediation steps, not to rescore the finding.

Rules:
- NEVER invent or adjust numeric scores. Reason only from the given signals.
- NEVER change the supplied SSVC decision, priority, or service-level target.
- Distinguish observed exploitation (KEV/PoC) from predictive EPSS evidence.
- No available fix means mitigation or investigation, not patching.
- Call out low-confidence SSVC inputs that need human confirmation.
- Be concise and concrete. Output via the ` + "`triage`" + ` tool only.
`

var aiActions = []string{"patch_immediately", "patch_out_of_cycle", "patch_scheduled", "mitigate", "monitor", "investigate"}

// TriageTool is the structured output schema.
var TriageTool = ai.Tool{
	"name":        "triage",
	"description": "Record the triage decision for one finding.",
	"strict":      true,
	"input_schema": map[string]any{
		"type": "object",
		"properties": map[string]any{
			"action":            map[string]any{"type": "string", "enum": aiActions},
			"rationale":         map[string]any{"type": "string", "maxLength": 2000, "description": "2-3 sentences citing SSVC inputs"},
			"remediation_steps": map[string]any{"type": "array", "items": map[string]any{"type": "string", "maxLength": 2000}, "maxItems": 5},
			"uncertainties":     map[string]any{"type": "array", "items": map[string]any{"type": "string", "maxLength": 2000}, "maxItems": 5},
		},
		"required":             []string{"action", "rationale", "remediation_steps", "uncertainties"},
		"additionalProperties": false,
	},
}

// Backend triages one finding.
type Backend interface {
	Triage(ctx context.Context, f *model.Finding) (*model.Triage, error)
}

// RulesBackend is the deterministic SSVC Deployer decision.
type RulesBackend struct{}

func (RulesBackend) Triage(_ context.Context, f *model.Finding) (*model.Triage, error) {
	return decision.Triage(f), nil
}

// findingPayload is the finding (without its triage) plus the
// deterministic assessment the model must explain.
func findingPayload(f *model.Finding) (string, error) {
	raw, err := json.Marshal(f)
	if err != nil {
		return "", err
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", err
	}
	delete(payload, "triage")
	description := []rune(f.Description)
	payload["description"] = string(description[:min(600, len(description))])
	payload["ssvc_assessment"] = decision.Assess(f)
	out, err := json.Marshal(payload)
	return string(out), err
}

// validateRecommendation enforces the tool schema locally across providers.
func validateRecommendation(r map[string]any) (map[string]any, error) {
	if r == nil {
		return nil, errors.New("AI provider returned a non-object recommendation")
	}
	fields := []string{"action", "rationale", "remediation_steps", "uncertainties"}
	if len(r) != len(fields) {
		return nil, errors.New("AI provider returned missing or unexpected recommendation fields")
	}
	for _, k := range fields {
		if _, ok := r[k]; !ok {
			return nil, errors.New("AI provider returned missing or unexpected recommendation fields")
		}
	}
	action, _ := r["action"].(string)
	if !slices.Contains(aiActions, action) {
		raw, _ := json.Marshal(r["action"])
		return nil, fmt.Errorf("AI provider returned invalid action: %s", raw)
	}
	rationale, ok := r["rationale"].(string)
	if !ok || strings.TrimSpace(rationale) == "" || len([]rune(rationale)) > 2000 {
		return nil, errors.New("AI provider returned an invalid rationale")
	}
	out := map[string]any{"action": action, "rationale": strings.TrimSpace(rationale)}
	for _, field := range []string{"remediation_steps", "uncertainties"} {
		values, ok := r[field].([]any)
		if !ok || len(values) > 5 {
			return nil, fmt.Errorf("AI provider returned invalid %s; expected up to 5 strings", field)
		}
		cleaned := []string{}
		for _, v := range values {
			s, ok := v.(string)
			if !ok || len([]rune(s)) > 2000 {
				return nil, fmt.Errorf("AI provider returned invalid %s; expected up to 5 strings", field)
			}
			if s = strings.TrimSpace(s); s != "" {
				cleaned = append(cleaned, s)
			}
		}
		out[field] = cleaned
	}
	return out, nil
}

// mergeRecommendation keeps the SSVC decision authoritative and attaches
// the AI assistance.
func mergeRecommendation(f *model.Finding, r map[string]any, backend string) *model.Triage {
	t := decision.Triage(f)
	t.Backend = backend
	if rationale, _ := r["rationale"].(string); rationale != "" {
		t.Rationale = rationale
	}
	action, _ := r["action"].(string)
	steps, _ := r["remediation_steps"].([]string)
	notes, _ := r["uncertainties"].([]string)
	t.AIRecommendation = &model.AIRecommendation{Action: action, RemediationSteps: nonNil(steps), Uncertainties: nonNil(notes)}
	return t
}

// AIBackend is a provider-neutral structured explanation backend.
type AIBackend struct {
	Provider ai.Provider
	Model    string
}

// NewAIBackend resolves the provider and the deep-tier model.
func NewAIBackend(modelName, provider, baseURL string) (*AIBackend, error) {
	name, err := ai.ResolveProviderName(provider)
	if err != nil {
		return nil, err
	}
	client, err := ai.MakeProvider(firstNonEmpty(provider, name), baseURL)
	if err != nil {
		return nil, err
	}
	resolved, err := ai.ResolveModel(name, modelName, "deep")
	if err != nil {
		return nil, err
	}
	return &AIBackend{Provider: client, Model: resolved}, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func (b *AIBackend) Triage(ctx context.Context, f *model.Finding) (*model.Triage, error) {
	payload, err := findingPayload(f)
	if err != nil {
		return nil, err
	}
	raw, err := b.Provider.Complete(ctx, b.Model, TriageSystemPrompt, payload, TriageTool)
	if err != nil {
		return nil, err
	}
	r, err := validateRecommendation(raw)
	if err != nil {
		return nil, err
	}
	return mergeRecommendation(f, r, b.Provider.Name()+":"+b.Model), nil
}

// CascadeBackend screens every finding with a fast model and re-triages
// with the deeper one when the finding is SSVC-urgent, rests on an input
// needing confirmation, or its screening explanation failed the audit. The
// routing decision and its reasons are recorded.
type CascadeBackend struct {
	Screen, Deep Backend
}

// NewCascadeBackend shares one provider between the two tiers.
func NewCascadeBackend(screenModel, deepModel, provider, baseURL string) (*CascadeBackend, error) {
	name, err := ai.ResolveProviderName(provider)
	if err != nil {
		return nil, err
	}
	client, err := ai.MakeProvider(firstNonEmpty(provider, name), baseURL)
	if err != nil {
		return nil, err
	}
	screen, err := ai.ResolveModel(name, screenModel, "screen")
	if err != nil {
		return nil, err
	}
	deep, err := ai.ResolveModel(name, deepModel, "deep")
	if err != nil {
		return nil, err
	}
	return &CascadeBackend{Screen: &AIBackend{client, screen}, Deep: &AIBackend{client, deep}}, nil
}

func (c *CascadeBackend) escalationReasons(f *model.Finding, tentative *model.Triage) []string {
	var reasons []string
	a := decision.Assess(f)
	if a.Priority == "P1" || a.Priority == "P2" {
		reasons = append(reasons, "ssvc_"+a.Decision)
	}
	if len(a.NeedsConfirmation) > 0 {
		reasons = append(reasons, "ssvc_confirmation:"+strings.Join(a.NeedsConfirmation, ","))
	}
	previous := f.Triage
	f.Triage = tentative
	result := AuditFinding(f)
	f.Triage = previous
	if result["verified"] != true {
		reasons = append(reasons, "audit_flags:"+strings.Join(result["flags"].([]string), ","))
	}
	return reasons
}

func (c *CascadeBackend) Triage(ctx context.Context, f *model.Finding) (*model.Triage, error) {
	result, err := c.Screen.Triage(ctx, f)
	if err != nil {
		return nil, err
	}
	reasons := c.escalationReasons(f, result)
	escalated := len(reasons) > 0
	if escalated {
		if result, err = c.Deep.Triage(ctx, f); err != nil {
			return nil, err
		}
		result.EscalationReasons = reasons
	}
	result.Escalated = &escalated
	return result, nil
}

// TriageOptions select the triage backend for an assessment.
type TriageOptions struct {
	Backend         string // rules | ai | claude | cascade
	Model           string // ai: model; cascade: screening model
	EscalationModel string // cascade: deep model
	Provider        string
	BaseURL         string
	Jobs            int
	Batch           bool // Anthropic Message Batches API
}

// GetBackend builds the named backend.
func GetBackend(o TriageOptions) (Backend, error) {
	switch o.Backend {
	case "", "rules":
		return RulesBackend{}, nil
	case "claude":
		return NewAIBackend(o.Model, "anthropic", "")
	case "ai":
		return NewAIBackend(o.Model, o.Provider, o.BaseURL)
	case "cascade":
		return NewCascadeBackend(o.Model, o.EscalationModel, o.Provider, o.BaseURL)
	}
	return nil, fmt.Errorf("Unknown triage backend: %s", o.Backend)
}

// fallback is the deterministic baseline tagged with why the backend failed.
func fallback(f *model.Finding, reason string) *model.Triage {
	t := decision.Triage(f)
	t.Backend = "rules_fallback"
	t.Error = string([]rune(reason)[:min(300, len([]rune(reason)))])
	return t
}

// errorName labels an error like Python's type(exc).__name__.
func errorName(err error) string {
	var apiErr *ai.APIError
	switch {
	case errors.As(err, &apiErr):
		return "APIStatusError"
	case errors.Is(err, context.DeadlineExceeded):
		return "TimeoutError"
	}
	return "RuntimeError"
}

// RunTriage triages every finding in place across jobs workers. The rules
// backend never falls back: a bug in the baseline must not be masked.
func RunTriage(ctx context.Context, findings []*model.Finding, backend Backend, jobs int, progress func(done, total int)) error {
	if _, isRules := backend.(RulesBackend); isRules {
		for i, f := range findings {
			t, _ := backend.Triage(ctx, f)
			f.Triage = t
			if progress != nil {
				progress(i+1, len(findings))
			}
		}
		return nil
	}
	results := make([]*model.Triage, len(findings))
	work := make(chan int)
	var wg sync.WaitGroup
	var mu sync.Mutex
	done := 0
	for range max(1, jobs) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range work {
				t, err := backend.Triage(ctx, findings[i])
				if err != nil {
					t = fallback(findings[i], errorName(err)+": "+err.Error())
				}
				results[i] = t
				mu.Lock()
				done++
				if progress != nil {
					progress(done, len(findings))
				}
				mu.Unlock()
			}
		}()
	}
	for i := range findings {
		work <- i
	}
	close(work)
	wg.Wait()
	for i, f := range findings {
		f.Triage = results[i]
	}
	return nil
}

// RunTriageBatch triages through the Anthropic Message Batches API. Entries
// that error or expire keep the SSVC baseline, as RunTriage does.
func RunTriageBatch(ctx context.Context, findings []*model.Finding, modelName, provider string, poll time.Duration,
	progress func(string)) error {
	name, err := ai.ResolveProviderName(provider)
	if err != nil {
		return err
	}
	if name != "anthropic" {
		return errors.New("Batch mode currently requires the Anthropic provider; use regular parallel mode for " +
			"OpenAI-compatible endpoints")
	}
	if modelName, err = ai.ResolveModel(name, modelName, "deep"); err != nil {
		return err
	}
	client, err := ai.NewAnthropic()
	if err != nil {
		return err
	}
	requests := make([]ai.BatchRequest, len(findings))
	for i, f := range findings {
		payload, err := findingPayload(f)
		if err != nil {
			return err
		}
		requests[i] = ai.BatchRequest{CustomID: fmt.Sprintf("finding-%d", i),
			Params: ai.MessageParams(modelName, TriageSystemPrompt, payload, TriageTool)}
	}
	results, err := client.RunBatch(ctx, requests, "triage", poll, progress)
	if err != nil {
		return err
	}
	for i, f := range findings {
		raw, ok := results[fmt.Sprintf("finding-%d", i)]
		if !ok {
			f.Triage = fallback(f, "batch entry errored or expired")
			continue
		}
		r, err := validateRecommendation(raw)
		if err != nil {
			return err // Python raises on an invalid batch recommendation
		}
		f.Triage = mergeRecommendation(f, r, "anthropic:"+modelName+" (batch)")
	}
	return nil
}
