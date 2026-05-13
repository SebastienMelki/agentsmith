package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}

func TestLoad_DefaultsAppliedAndTargetsRequired(t *testing.T) {
	path := writeConfig(t, `
targets:
  - name: only
    url: http://127.0.0.1:8000/mcp
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ListenAddr != ":3001" {
		t.Errorf("default ListenAddr = %q, want :3001", cfg.ListenAddr)
	}
	if cfg.AdminAddr != ":3002" {
		t.Errorf("default AdminAddr = %q, want :3002", cfg.AdminAddr)
	}
	if cfg.Path != "/mcp" {
		t.Errorf("default Path = %q, want /mcp", cfg.Path)
	}
	if len(cfg.Targets) != 1 || cfg.Targets[0].Name != "only" {
		t.Errorf("targets = %+v", cfg.Targets)
	}
}

func TestLoad_NoTargetsIsError(t *testing.T) {
	path := writeConfig(t, `listenAddr: ":3001"`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for empty targets, got nil")
	}
}

func TestLoad_TargetMissingURLIsError(t *testing.T) {
	path := writeConfig(t, `
targets:
  - name: broken
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for missing url, got nil")
	}
	if !strings.Contains(err.Error(), "url") {
		t.Errorf("error %q should mention 'url'", err.Error())
	}
}

func TestLoad_EnvInterpolationSuccess(t *testing.T) {
	t.Setenv("AGENTSMITH_TEST_TOKEN", "s3cret")
	path := writeConfig(t, `
targets:
  - name: api
    url: http://127.0.0.1:9000/mcp
    headers:
      Authorization: Bearer ${AGENTSMITH_TEST_TOKEN}
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := cfg.Targets[0].Headers["Authorization"]
	if got != "Bearer s3cret" {
		t.Errorf("interpolated header = %q, want %q", got, "Bearer s3cret")
	}
}

func TestLoad_EnvInterpolationMissingVarIsError(t *testing.T) {
	// Variable name chosen so it is virtually guaranteed to be unset.
	path := writeConfig(t, `
targets:
  - name: api
    url: http://127.0.0.1:9000/mcp
    headers:
      Authorization: Bearer ${AGENTSMITH_DEFINITELY_UNSET_XYZ}
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for unset env var, got nil")
	}
	if !strings.Contains(err.Error(), "AGENTSMITH_DEFINITELY_UNSET_XYZ") {
		t.Errorf("error %q should name the missing variable", err.Error())
	}
}

func TestLoad_MalformedYAMLIsError(t *testing.T) {
	path := writeConfig(t, "this: is: not: valid: yaml:\n  - and: also: bad")
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for malformed YAML, got nil")
	}
}

func TestLoad_MissingFileIsError(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml")); err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestLoad_DefaultAuthModeIsUnprotected(t *testing.T) {
	path := writeConfig(t, `
targets:
  - name: only
    url: http://127.0.0.1:8000/mcp
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AuthMode != ModeUnprotected {
		t.Errorf("AuthMode = %q, want %q", cfg.AuthMode, ModeUnprotected)
	}
}

func TestLoad_InvalidAuthModeIsError(t *testing.T) {
	path := writeConfig(t, `
authMode: weirdmode
targets:
  - name: only
    url: http://127.0.0.1:8000/mcp
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid authMode, got nil")
	}
	if !strings.Contains(err.Error(), "weirdmode") {
		t.Errorf("error %q should name the bad value", err.Error())
	}
}

func TestLoad_OAuthTargetRequiresCallbackBaseURL(t *testing.T) {
	path := writeConfig(t, `
targets:
  - name: slack
    url: http://127.0.0.1:8000/mcp
    auth:
      type: oauth
      clientId: abc
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for oauth target without callbackBaseUrl, got nil")
	}
	if !strings.Contains(err.Error(), "callbackBaseUrl") {
		t.Errorf("error %q should mention callbackBaseUrl", err.Error())
	}
}

func TestLoad_OAuthTargetRequiresClientIDOrDCR(t *testing.T) {
	path := writeConfig(t, `
oauth:
  callbackBaseUrl: http://localhost:3002
targets:
  - name: slack
    url: http://127.0.0.1:8000/mcp
    auth:
      type: oauth
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for oauth target without clientId/DCR, got nil")
	}
	if !strings.Contains(err.Error(), "clientId") {
		t.Errorf("error %q should mention clientId", err.Error())
	}
}

func TestLoad_OAuthTargetHappyPath(t *testing.T) {
	t.Setenv("TEST_CLIENT_ID", "id123")
	t.Setenv("TEST_CLIENT_SECRET", "shh")
	path := writeConfig(t, `
authMode: protected
oauth:
  callbackBaseUrl: https://gateway.example.com
targets:
  - name: slack
    url: https://slack.example.com/mcp
    auth:
      type: oauth
      clientId: ${TEST_CLIENT_ID}
      clientSecret: ${TEST_CLIENT_SECRET}
      scopes: [channels:read, chat:write]
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AuthMode != ModeProtected {
		t.Errorf("AuthMode = %q, want %q", cfg.AuthMode, ModeProtected)
	}
	if cfg.OAuth.CallbackBaseURL != "https://gateway.example.com" {
		t.Errorf("CallbackBaseURL = %q", cfg.OAuth.CallbackBaseURL)
	}
	if cfg.Targets[0].Auth == nil || cfg.Targets[0].Auth.ClientID != "id123" {
		t.Errorf("oauth client id not parsed; got %+v", cfg.Targets[0].Auth)
	}
}

func TestLoad_UnknownAuthTypeIsError(t *testing.T) {
	path := writeConfig(t, `
targets:
  - name: weird
    url: http://127.0.0.1:8000/mcp
    auth:
      type: nonsense
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for unknown auth type, got nil")
	}
}

func TestLoad_StaticBackendsStillWork(t *testing.T) {
	// Pre-existing config shape (no auth block) must continue to parse — this
	// is the upgrade-compat guarantee for existing deployments.
	t.Setenv("DODO_KEY", "abc")
	path := writeConfig(t, `
targets:
  - name: dodo
    url: http://127.0.0.1:8000/mcp
    headers:
      X-Dodo-API-Key: ${DODO_KEY}
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Targets[0].Auth != nil {
		t.Errorf("static target should have nil Auth, got %+v", cfg.Targets[0].Auth)
	}
	if cfg.Targets[0].Headers["X-Dodo-API-Key"] != "abc" {
		t.Errorf("static headers not preserved: %v", cfg.Targets[0].Headers)
	}
}
