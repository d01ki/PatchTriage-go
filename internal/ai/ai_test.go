package ai

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func clearAIEnv(t *testing.T) {
	t.Helper()
	for _, key := range EnvKeys {
		t.Setenv(key, "")
	}
}

func TestResolveProviderAndModel(t *testing.T) {
	clearAIEnv(t)
	if _, err := ResolveProviderName(""); err == nil || !strings.Contains(err.Error(), "No AI provider is configured") {
		t.Errorf("no provider: %v", err)
	}
	t.Setenv("ANTHROPIC_API_KEY", "k")
	if p, err := ResolveProviderName(""); p != "anthropic" || err != nil || !HasConfiguration() {
		t.Errorf("anthropic = %q, %v", p, err)
	}
	t.Setenv("OPENAI_API_KEY", "k")
	if _, err := ResolveProviderName(""); err == nil || !strings.Contains(err.Error(), "Multiple AI providers") {
		t.Errorf("ambiguous: %v", err)
	}
	if p, _ := ResolveProviderName("Ollama"); p != "openai-compatible" {
		t.Errorf("ollama alias = %q", p)
	}
	if _, err := NormalizeProviderName("bard"); err == nil || !strings.Contains(err.Error(), "choose one of: anthropic, claude") {
		t.Errorf("unknown provider: %v", err)
	}
	if m, _ := ResolveModel("anthropic", "", "screen"); m != AnthropicDefaultScreenModel {
		t.Errorf("screen model = %q", m)
	}
	t.Setenv("PATCHTRIAGE_AI_MODEL", "configured")
	if m, _ := ResolveModel("openai-compatible", "", "deep"); m != "configured" {
		t.Errorf("configured model = %q", m)
	}
	t.Setenv("PATCHTRIAGE_AI_MODEL", "")
	if _, err := ResolveModel("openai-compatible", "", "deep"); err == nil {
		t.Error("an OpenAI-compatible provider needs an explicit model")
	}
	if _, err := NewOpenAICompatible("", ""); err != nil {
		t.Errorf("OPENAI_API_KEY set: %v", err)
	}
	t.Setenv("OPENAI_API_KEY", "")
	if _, err := NewOpenAICompatible("", ""); err == nil {
		t.Error("the default OpenAI endpoint requires a key")
	}
}

func TestConfigRoundTripAndEnvironmentPrecedence(t *testing.T) {
	clearAIEnv(t)
	t.Setenv("PATCHTRIAGE_CONFIG_DIR", t.TempDir())
	if len(LoadConfig()) != 0 {
		t.Error("missing config should be empty")
	}
	path, err := SaveConfig(map[string]any{"ANTHROPIC_API_KEY": "saved", "NVD_API_KEY": "nvd", "default_backend": "ai"})
	if err != nil || path != ConfigPath() {
		t.Fatal(path, err)
	}
	t.Setenv("NVD_API_KEY", "from-env")
	ApplyToEnv(LoadConfig())
	if os.Getenv("ANTHROPIC_API_KEY") != "saved" || os.Getenv("NVD_API_KEY") != "from-env" {
		t.Errorf("env = %q %q", os.Getenv("ANTHROPIC_API_KEY"), os.Getenv("NVD_API_KEY"))
	}
	if err := os.WriteFile(ConfigPath(), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if len(LoadConfig()) != 0 {
		t.Error("corrupt config should be empty")
	}
}

func TestValidateKeyAndMask(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") == "good" || r.Header.Get("Authorization") == "Bearer good" {
			return
		}
		w.WriteHeader(401)
	}))
	defer server.Close()
	for _, provider := range []string{"anthropic", "openai"} {
		if ok, msg := ValidateKey(context.Background(), server.Client(), provider, server.URL, "good"); !ok || msg != "key is valid" {
			t.Errorf("%s good key: %v %s", provider, ok, msg)
		}
		if ok, msg := ValidateKey(context.Background(), server.Client(), provider, server.URL, "bad"); ok || !strings.Contains(msg, "401") {
			t.Errorf("%s bad key: %v %s", provider, ok, msg)
		}
	}
	if Mask("sk-ant-1234567890abcd") != "sk-ant-...abcd" || Mask("short") != "*****" {
		t.Errorf("mask = %q %q", Mask("sk-ant-1234567890abcd"), Mask("short"))
	}
}
