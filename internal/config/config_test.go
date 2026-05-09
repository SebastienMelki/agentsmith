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
