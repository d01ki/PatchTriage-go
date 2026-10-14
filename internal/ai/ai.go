// Package ai holds the optional AI provider adapters and the user
// configuration that stores their keys. The triage engine depends on the
// small Provider interface instead of a vendor SDK: Anthropic's Messages API
// and any OpenAI-compatible /chat/completions endpoint (OpenAI, Ollama and
// local gateways) are spoken over plain HTTP.
//
// Providers only explain: the deterministic SSVC decision is final and is
// never rescored by a model.
package ai

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/d01ki/PatchTriage-go/internal/enrich"
)

const (
	AnthropicDefaultModel       = "claude-opus-5-5"
	AnthropicDefaultScreenModel = "claude-haiku-5-5"
	OpenAIDefaultBaseURL        = "https://api.openai.com/v1"
	OllamaDefaultBaseURL        = "http://localhost:11434/v1"
	anthropicDefaultBaseURL     = "https://api.anthropic.com"
	anthropicVersion            = "2023-06-01"
	maxTokens                   = 1024
	anthropicTimeout            = 10 * time.Minute
	openAITimeout               = 60 * time.Second
	maxRetries                  = 2
	maxResponseBytes            = 64 * 1024 * 1024
)

var providerAliases = map[string]string{
	"anthropic": "anthropic", "claude": "anthropic", "openai": "openai-compatible",
	"openai-compatible": "openai-compatible", "ollama": "openai-compatible",
}

// Tool is a structured-output tool definition (Anthropic tool shape:
// name, description, strict, input_schema).
type Tool map[string]any

// Provider is the inference boundary consumed by the triage engine.
type Provider interface {
	Name() string
	// Complete returns the arguments of the forced tool call.
	Complete(ctx context.Context, model, systemPrompt, payload string, tool Tool) (map[string]any, error)
}

// NormalizeProviderName maps an alias onto anthropic or openai-compatible.
func NormalizeProviderName(name string) (string, error) {
	normalized := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(name)), "_", "-")
	if resolved, ok := providerAliases[normalized]; ok {
		return resolved, nil
	}
	choices := make([]string, 0, len(providerAliases))
	for alias := range providerAliases {
		choices = append(choices, alias)
	}
	sort.Strings(choices)
	return "", fmt.Errorf("Unknown AI provider '%s'; choose one of: %s", name, strings.Join(choices, ", "))
}

// ResolveProviderName resolves an explicit provider or infers the only
// configured one.
func ResolveProviderName(name string) (string, error) {
	if name == "" {
		name = os.Getenv("PATCHTRIAGE_AI_PROVIDER")
	}
	if name != "" {
		return NormalizeProviderName(name)
	}
	var configured []string
	if os.Getenv("ANTHROPIC_API_KEY") != "" {
		configured = append(configured, "anthropic")
	}
	if os.Getenv("OPENAI_API_KEY") != "" || os.Getenv("PATCHTRIAGE_AI_API_KEY") != "" || os.Getenv("PATCHTRIAGE_AI_BASE_URL") != "" {
		configured = append(configured, "openai-compatible")
	}
	switch len(configured) {
	case 1:
		return configured[0], nil
	case 0:
		return "", errors.New("No AI provider is configured. Set PATCHTRIAGE_AI_PROVIDER and the provider API key/base " +
			"URL, or use the deterministic 'rules' backend.")
	}
	return "", errors.New("Multiple AI providers are configured; set PATCHTRIAGE_AI_PROVIDER explicitly")
}

// ResolveModel resolves a model without hard-coding another vendor's
// catalog. tier is "screen" or "deep".
func ResolveModel(provider, requested, tier string) (string, error) {
	if requested != "" {
		return requested, nil
	}
	configured := os.Getenv("PATCHTRIAGE_AI_SCREEN_MODEL")
	if tier != "screen" {
		configured = os.Getenv("PATCHTRIAGE_AI_DEEP_MODEL")
		if configured == "" {
			configured = os.Getenv("PATCHTRIAGE_AI_MODEL")
		}
	}
	switch {
	case configured != "":
		return configured, nil
	case provider == "anthropic" && tier == "screen":
		return AnthropicDefaultScreenModel, nil
	case provider == "anthropic":
		return AnthropicDefaultModel, nil
	}
	return "", errors.New("An AI model is required for an OpenAI-compatible provider. Pass --model or set " +
		"PATCHTRIAGE_AI_MODEL; cascade can additionally use PATCHTRIAGE_AI_SCREEN_MODEL and PATCHTRIAGE_AI_DEEP_MODEL.")
}

// HasConfiguration reports whether the environment can construct a usable
// AI backend.
func HasConfiguration() bool {
	provider, err := ResolveProviderName("")
	if err != nil {
		return false
	}
	if _, err := ResolveModel(provider, "", "deep"); err != nil {
		return false
	}
	if provider == "anthropic" {
		return os.Getenv("ANTHROPIC_API_KEY") != ""
	}
	return os.Getenv("PATCHTRIAGE_AI_BASE_URL") != "" || os.Getenv("OPENAI_API_KEY") != "" ||
		os.Getenv("PATCHTRIAGE_AI_API_KEY") != "" ||
		strings.ToLower(strings.TrimSpace(os.Getenv("PATCHTRIAGE_AI_PROVIDER"))) == "ollama"
}

// MakeProvider builds the provider for name (or the configured one).
func MakeProvider(name, baseURL string) (Provider, error) {
	resolved, err := ResolveProviderName(name)
	if err != nil {
		return nil, err
	}
	if resolved == "anthropic" {
		return NewAnthropic()
	}
	if strings.ToLower(strings.TrimSpace(name)) == "ollama" && baseURL == "" {
		baseURL = OllamaDefaultBaseURL
	}
	return NewOpenAICompatible(baseURL, "")
}

// ------------------------------------------------------------------ HTTP

// APIError is a non-success provider response.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string { return e.Message }

func retryable(status int) bool {
	return status == 408 || status == 409 || status == 429 || status >= 500
}

// do sends one JSON request, retrying transient failures with backoff and
// honoring Retry-After, and returns the bounded response body.
func do(ctx context.Context, client *http.Client, method, url string, headers map[string]string, body any, timeout time.Duration) ([]byte, error) {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return nil, err
		}
	}
	for attempt := 0; ; attempt++ {
		raw, status, wait, err := doOnce(ctx, client, method, url, headers, payload, timeout)
		if err == nil || attempt >= maxRetries || (status != 0 && !retryable(status)) {
			return raw, err
		}
		if wait == 0 {
			wait = time.Duration(1<<attempt) * 500 * time.Millisecond
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(min(wait, 60*time.Second)):
		}
	}
}

func doOnce(ctx context.Context, client *http.Client, method, url string, headers map[string]string, payload []byte,
	timeout time.Duration) ([]byte, int, time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var reader io.Reader
	if payload != nil {
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return nil, 0, 0, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, 0, 0, err
	}
	if len(raw) > maxResponseBytes {
		return nil, resp.StatusCode, 0, fmt.Errorf("response from %s exceeds %d bytes", url, maxResponseBytes)
	}
	if statusErr := enrich.StatusError(resp); statusErr != nil {
		var wait time.Duration
		if seconds, err := strconv.ParseFloat(resp.Header.Get("Retry-After"), 64); err == nil && seconds >= 0 {
			wait = time.Duration(seconds * float64(time.Second))
		}
		return nil, resp.StatusCode, wait, &APIError{StatusCode: resp.StatusCode, Message: statusErr.Error()}
	}
	return raw, resp.StatusCode, 0, nil
}

// ------------------------------------------------------------------ Anthropic

// Anthropic is the Messages API adapter.
type Anthropic struct {
	HTTP    *http.Client
	BaseURL string
	APIKey  string
}

// NewAnthropic reads ANTHROPIC_API_KEY (and ANTHROPIC_BASE_URL, like the SDK).
func NewAnthropic() (*Anthropic, error) {
	key := os.Getenv("ANTHROPIC_API_KEY")
	if key == "" {
		return nil, errors.New("Could not create an Anthropic client. Set ANTHROPIC_API_KEY and retry.")
	}
	base := os.Getenv("ANTHROPIC_BASE_URL")
	if base == "" {
		base = anthropicDefaultBaseURL
	}
	return &Anthropic{HTTP: &http.Client{}, BaseURL: strings.TrimRight(base, "/"), APIKey: key}, nil
}

func (a *Anthropic) Name() string { return "anthropic" }

func (a *Anthropic) headers() map[string]string {
	return map[string]string{"x-api-key": a.APIKey, "anthropic-version": anthropicVersion, "content-type": "application/json"}
}

// MessageParams is one Messages API request: the system prompt is cached and
// the triage tool is forced.
func MessageParams(model, systemPrompt, payload string, tool Tool) map[string]any {
	return map[string]any{
		"model": model, "max_tokens": maxTokens,
		"system":      []map[string]any{{"type": "text", "text": systemPrompt, "cache_control": map[string]string{"type": "ephemeral"}}},
		"messages":    []map[string]any{{"role": "user", "content": payload}},
		"tools":       []Tool{tool},
		"tool_choice": map[string]string{"type": "tool", "name": tool["name"].(string)},
	}
}

type message struct {
	Content []struct {
		Type  string          `json:"type"`
		Name  string          `json:"name"`
		Input json.RawMessage `json:"input"`
	} `json:"content"`
}

// toolInput returns the input of the named tool_use block.
func (m message) toolInput(name string) (map[string]any, bool) {
	for _, block := range m.Content {
		if block.Type == "tool_use" && block.Name == name {
			var input map[string]any
			if json.Unmarshal(block.Input, &input) == nil && input != nil {
				return input, true
			}
		}
	}
	return nil, false
}

func (a *Anthropic) Complete(ctx context.Context, model, systemPrompt, payload string, tool Tool) (map[string]any, error) {
	raw, err := do(ctx, a.HTTP, http.MethodPost, a.BaseURL+"/v1/messages", a.headers(),
		MessageParams(model, systemPrompt, payload, tool), anthropicTimeout)
	if err != nil {
		return nil, err
	}
	var m message
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("Anthropic returned an invalid response: %w", err)
	}
	if input, ok := m.toolInput(tool["name"].(string)); ok {
		return input, nil
	}
	return nil, errors.New("Anthropic returned no triage tool-use block")
}

// BatchRequest is one Message Batches entry.
type BatchRequest struct {
	CustomID string         `json:"custom_id"`
	Params   map[string]any `json:"params"`
}

// RunBatch submits requests to the Message Batches API (half the standard
// cost), polls until the batch ends and returns the named tool's input per
// succeeded custom_id. Results are keyed by custom_id, never by position.
func (a *Anthropic) RunBatch(ctx context.Context, requests []BatchRequest, toolName string, poll time.Duration,
	progress func(string)) (map[string]map[string]any, error) {
	type batch struct {
		ID               string `json:"id"`
		ProcessingStatus string `json:"processing_status"`
		RequestCounts    struct {
			Processing int `json:"processing"`
		} `json:"request_counts"`
		ResultsURL string `json:"results_url"`
	}
	raw, err := do(ctx, a.HTTP, http.MethodPost, a.BaseURL+"/v1/messages/batches", a.headers(),
		map[string]any{"requests": requests}, anthropicTimeout)
	if err != nil {
		return nil, err
	}
	var b batch
	if err := json.Unmarshal(raw, &b); err != nil || b.ID == "" {
		return nil, errors.New("Anthropic returned an invalid batch")
	}
	progress(fmt.Sprintf("batch %s submitted (%d findings)", b.ID, len(requests)))
	for b.ProcessingStatus != "ended" {
		progress(fmt.Sprintf("batch %s: %s (%d processing)", b.ID, b.ProcessingStatus, b.RequestCounts.Processing))
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(poll):
		}
		if raw, err = do(ctx, a.HTTP, http.MethodGet, a.BaseURL+"/v1/messages/batches/"+b.ID, a.headers(), nil, anthropicTimeout); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &b); err != nil {
			return nil, errors.New("Anthropic returned an invalid batch")
		}
	}
	resultsURL := b.ResultsURL
	if resultsURL == "" {
		resultsURL = a.BaseURL + "/v1/messages/batches/" + b.ID + "/results"
	}
	if raw, err = do(ctx, a.HTTP, http.MethodGet, resultsURL, a.headers(), nil, anthropicTimeout); err != nil {
		return nil, err
	}
	out := map[string]map[string]any{}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 1024*1024), maxResponseBytes)
	for scanner.Scan() {
		var line struct {
			CustomID string `json:"custom_id"`
			Result   struct {
				Type    string  `json:"type"`
				Message message `json:"message"`
			} `json:"result"`
		}
		if json.Unmarshal(scanner.Bytes(), &line) != nil || line.Result.Type != "succeeded" {
			continue
		}
		if input, ok := line.Result.Message.toolInput(toolName); ok {
			out[line.CustomID] = input
		}
	}
	return out, scanner.Err()
}

// ------------------------------------------------------------------ OpenAI-compatible

// OpenAICompatible is the Chat Completions adapter.
type OpenAICompatible struct {
	HTTP    *http.Client
	BaseURL string
	APIKey  string
}

// NewOpenAICompatible resolves the base URL and key from arguments, then the
// environment.
func NewOpenAICompatible(baseURL, apiKey string) (*OpenAICompatible, error) {
	switch {
	case baseURL != "":
	case os.Getenv("PATCHTRIAGE_AI_BASE_URL") != "":
		baseURL = os.Getenv("PATCHTRIAGE_AI_BASE_URL")
	case strings.ToLower(strings.TrimSpace(os.Getenv("PATCHTRIAGE_AI_PROVIDER"))) == "ollama":
		baseURL = OllamaDefaultBaseURL
	default:
		baseURL = OpenAIDefaultBaseURL
	}
	baseURL = strings.TrimRight(baseURL, "/")
	if apiKey == "" {
		apiKey = os.Getenv("PATCHTRIAGE_AI_API_KEY")
	}
	if apiKey == "" {
		apiKey = os.Getenv("OPENAI_API_KEY")
	}
	if baseURL == OpenAIDefaultBaseURL && apiKey == "" {
		return nil, errors.New("OPENAI_API_KEY or PATCHTRIAGE_AI_API_KEY is required for the default OpenAI endpoint")
	}
	return &OpenAICompatible{HTTP: &http.Client{}, BaseURL: baseURL, APIKey: apiKey}, nil
}

func (o *OpenAICompatible) Name() string { return "openai-compatible" }

func (o *OpenAICompatible) Complete(ctx context.Context, model, systemPrompt, payload string, tool Tool) (map[string]any, error) {
	name := tool["name"].(string)
	strict := true
	if s, ok := tool["strict"].(bool); ok {
		strict = s
	}
	description, _ := tool["description"].(string)
	body := map[string]any{
		"model":    model,
		"messages": []map[string]string{{"role": "system", "content": systemPrompt}, {"role": "user", "content": payload}},
		"tools": []map[string]any{{"type": "function", "function": map[string]any{
			"name": name, "description": description, "parameters": tool["input_schema"], "strict": strict}}},
		"tool_choice": map[string]any{"type": "function", "function": map[string]string{"name": name}},
	}
	headers := map[string]string{"Content-Type": "application/json"}
	if o.APIKey != "" {
		headers["Authorization"] = "Bearer " + o.APIKey
	}
	raw, err := do(ctx, o.HTTP, http.MethodPost, o.BaseURL+"/chat/completions", headers, body, openAITimeout)
	if err != nil {
		return nil, err
	}
	var response struct {
		Choices []struct {
			Message *struct {
				ToolCalls []struct {
					Function struct {
						Name      string          `json:"name"`
						Arguments json.RawMessage `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
	}
	if json.Unmarshal(raw, &response) != nil || len(response.Choices) == 0 || response.Choices[0].Message == nil {
		return nil, errors.New("OpenAI-compatible endpoint returned an invalid response")
	}
	for _, call := range response.Choices[0].Message.ToolCalls {
		if call.Function.Name != name {
			continue
		}
		arguments := call.Function.Arguments
		var text string
		if json.Unmarshal(arguments, &text) == nil {
			if !json.Valid([]byte(text)) {
				return nil, errors.New("OpenAI-compatible endpoint returned invalid tool JSON")
			}
			arguments = json.RawMessage(text)
		}
		var args map[string]any
		if json.Unmarshal(arguments, &args) == nil && args != nil {
			return args, nil
		}
	}
	return nil, errors.New("OpenAI-compatible endpoint returned no triage tool call")
}

// ------------------------------------------------------------------ configuration

// EnvKeys are the saved values mirrored into the environment for provider
// and enrichment clients.
var EnvKeys = []string{"PATCHTRIAGE_AI_PROVIDER", "PATCHTRIAGE_AI_API_KEY", "PATCHTRIAGE_AI_BASE_URL",
	"PATCHTRIAGE_AI_MODEL", "PATCHTRIAGE_AI_SCREEN_MODEL", "PATCHTRIAGE_AI_DEEP_MODEL", "ANTHROPIC_API_KEY",
	"OPENAI_API_KEY", "NVD_API_KEY", "GITHUB_TOKEN"}

// ConfigDir honors PATCHTRIAGE_CONFIG_DIR, else ~/.config/patchtriage-go.
func ConfigDir() string {
	if dir := os.Getenv("PATCHTRIAGE_CONFIG_DIR"); dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".config", "patchtriage-go")
}

// ConfigPath is the JSON file `patchtriage setup` writes.
func ConfigPath() string { return filepath.Join(ConfigDir(), "config.json") }

// LoadConfig returns the saved configuration; a missing or corrupt file is
// an empty configuration.
func LoadConfig() map[string]any {
	raw, err := os.ReadFile(ConfigPath())
	if err != nil {
		return map[string]any{}
	}
	var cfg map[string]any
	if json.Unmarshal(raw, &cfg) != nil || cfg == nil {
		return map[string]any{}
	}
	return cfg
}

// SaveConfig writes the configuration privately (0600; keys inside).
func SaveConfig(cfg map[string]any) (string, error) {
	if err := os.MkdirAll(ConfigDir(), 0o700); err != nil {
		return "", err
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	path := ConfigPath()
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return "", err
	}
	_ = os.Chmod(path, 0o600)
	return path, nil
}

// ApplyToEnv exports saved keys unless the environment already sets them:
// environment variables always win, so CI and containers keep working.
func ApplyToEnv(cfg map[string]any) {
	for _, key := range EnvKeys {
		if value, _ := cfg[key].(string); value != "" && os.Getenv(key) == "" {
			_ = os.Setenv(key, value)
		}
	}
}

// ValidateKey checks a key against the provider's models endpoint without
// spending tokens. provider is "anthropic" or "openai".
func ValidateKey(ctx context.Context, client *http.Client, provider, url, key string) (bool, string) {
	headers := map[string]string{"Authorization": "Bearer " + key}
	if provider == "anthropic" {
		headers = map[string]string{"x-api-key": key, "anthropic-version": anthropicVersion}
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, "network error: " + err.Error()
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, "network error: " + err.Error()
	}
	resp.Body.Close()
	switch resp.StatusCode {
	case 200:
		return true, "key is valid"
	case 401:
		return false, "authentication failed (401) - check the key"
	}
	return false, fmt.Sprintf("unexpected response: HTTP %d", resp.StatusCode)
}

// Mask shows only a secret's edges.
func Mask(secret string) string {
	if len(secret) <= 10 {
		return strings.Repeat("*", len(secret))
	}
	return secret[:7] + "..." + secret[len(secret)-4:]
}
