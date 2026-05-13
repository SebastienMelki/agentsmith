// Package config loads and validates the agentsmith YAML configuration file,
// expanding ${VAR} placeholders from the environment before parsing.
package config

import (
	"errors"
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

// AuthMode selects how the MCP endpoint authenticates incoming clients.
type AuthMode string

const (
	// ModeUnprotected accepts any caller on the MCP endpoint and pins every
	// OAuth identity to a single synthetic user. Matches the gateway's
	// historical behaviour; the admin UI shows a warning banner.
	ModeUnprotected AuthMode = "unprotected"
	// ModeProtected requires Authorization: Bearer <api_key> on the MCP
	// endpoint and stores OAuth tokens per resolved user.
	ModeProtected AuthMode = "protected"
)

// TargetAuth configures how the gateway authenticates *to* an upstream backend.
// A nil value (or Type == "static") means "use the static Headers map" — the
// pre-OAuth behaviour. Type == "oauth" makes the gateway perform an OAuth 2.1
// authorization-code flow per end user.
//
// ClientID and ClientSecret are optional. When ClientID is empty, the gateway
// runs RFC 7591 Dynamic Client Registration against the discovered
// registration_endpoint on the first connect — matching what MCP clients like
// Claude Desktop do. Provide explicit values only when the upstream does not
// support DCR.
type TargetAuth struct {
	Type             string   `yaml:"type"`
	ClientID         string   `yaml:"clientId"`
	ClientSecret     string   `yaml:"clientSecret"`
	Scopes           []string `yaml:"scopes"`
	AuthorizationURL string   `yaml:"authorizationUrl"`
	TokenURL         string   `yaml:"tokenUrl"`
}

const (
	// AuthTypeStatic is the implicit auth type when Auth is nil.
	AuthTypeStatic = "static"
	// AuthTypeOAuth selects the OAuth 2.1 authorization-code flow.
	AuthTypeOAuth = "oauth"
)

// Target describes one MCP backend that agentsmith federates.
type Target struct {
	Name    string            `yaml:"name"`
	URL     string            `yaml:"url"`
	Headers map[string]string `yaml:"headers"`
	Auth    *TargetAuth       `yaml:"auth"`
}

// OAuthConfig holds gateway-wide OAuth settings.
//
// CallbackBaseURL is an OPTIONAL override for the gateway's public URL used
// to build the OAuth redirect_uri sent to upstream authorization servers.
// When empty (the default), the gateway derives the base URL from the
// incoming /oauth/connect request — honouring X-Forwarded-Proto and
// X-Forwarded-Host so it works behind reverse proxies. Set this only when
// auto-detection fails (e.g. proxy strips forwarded headers).
//
// TicketKey signs the short-lived ticket embedded in connect URLs so the
// gateway can identify the user from a plain browser without re-auth.
type OAuthConfig struct {
	CallbackBaseURL string `yaml:"callbackBaseUrl"`
	TicketKey       string `yaml:"ticketKey"`
}

// Config is the top-level agentsmith configuration.
type Config struct {
	ListenAddr string      `yaml:"listenAddr"`
	AdminAddr  string      `yaml:"adminAddr"`
	Path       string      `yaml:"path"`
	AuthMode   AuthMode    `yaml:"authMode"`
	OAuth      OAuthConfig `yaml:"oauth"`
	Targets    []Target    `yaml:"targets"`
}

// Load reads the YAML file at path, expands ${VAR} environment references,
// and returns a validated Config. It returns an error if the file is missing,
// any referenced environment variable is unset, or required fields are absent.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path comes from a CLI flag, not user input
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	expanded, err := expandEnv(string(data))
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":3001"
	}
	if cfg.Path == "" {
		cfg.Path = "/mcp"
	}
	if cfg.AdminAddr == "" {
		cfg.AdminAddr = ":3002"
	}
	if cfg.AuthMode == "" {
		cfg.AuthMode = ModeUnprotected
	}
	if cfg.AuthMode != ModeUnprotected && cfg.AuthMode != ModeProtected {
		return nil, fmt.Errorf("authMode: %q is not a valid value (expected %q or %q)", cfg.AuthMode, ModeUnprotected, ModeProtected)
	}
	if len(cfg.Targets) == 0 {
		return nil, errors.New("at least one target is required")
	}
	for i, t := range cfg.Targets {
		if t.Name == "" || t.URL == "" {
			return nil, fmt.Errorf("targets[%d]: name and url are required", i)
		}
		if err := validateTargetAuth(t); err != nil {
			return nil, fmt.Errorf("targets[%d] (%s): %w", i, t.Name, err)
		}
	}
	return &cfg, nil
}

// validateTargetAuth ensures the auth block is internally consistent. The
// gateway can dial a static backend with nothing. For OAuth backends, no
// upfront credentials are required: if clientId is empty, the gateway will
// run Dynamic Client Registration (RFC 7591) against the discovered
// registration_endpoint on the first connect.
func validateTargetAuth(t Target) error {
	if t.Auth == nil || t.Auth.Type == "" || t.Auth.Type == AuthTypeStatic {
		return nil
	}
	if t.Auth.Type != AuthTypeOAuth {
		return fmt.Errorf("auth.type: %q is not a valid value", t.Auth.Type)
	}
	return nil
}

var envVarRe = regexp.MustCompile(`\$\{([A-Z_][A-Z0-9_]*)\}`)

// expandEnv replaces ${VAR} occurrences with their environment value, erroring
// if any referenced variable is unset. This avoids silently shipping a config
// with empty secrets.
func expandEnv(s string) (string, error) {
	var missing []string
	out := envVarRe.ReplaceAllStringFunc(s, func(m string) string {
		name := m[2 : len(m)-1]
		v, ok := os.LookupEnv(name)
		if !ok {
			missing = append(missing, name)
		}
		return v
	})
	if len(missing) > 0 {
		return "", fmt.Errorf("unset environment variables referenced by config: %v", missing)
	}
	return out, nil
}
