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
// CallbackBaseURL is the gateway's public URL used to build the OAuth
// redirect_uri sent to upstream authorization servers. Set this whenever the
// gateway sits behind a reverse proxy, NAT, or otherwise on a hostname that
// differs from what `r.Host` carries — production deployments should always
// set it. When empty, the redirect_uri is derived from the incoming request's
// scheme + Host, with no proxy-header magic.
//
// TrustForwardedHeaders, if true, lets the auto-derived base URL honour
// X-Forwarded-Proto and X-Forwarded-Host. Default is false because these
// headers are caller-controlled and let an attacker reaching a (mis-exposed)
// admin port redirect OAuth callbacks to an arbitrary host. Only enable when
// you know the admin port sits behind a proxy that strips/overwrites those
// headers; even then, prefer setting CallbackBaseURL explicitly.
//
// TicketKey signs the short-lived ticket embedded in connect URLs so the
// gateway can identify the user from a plain browser without re-auth.
type OAuthConfig struct {
	CallbackBaseURL       string `yaml:"callbackBaseUrl"`
	TrustForwardedHeaders bool   `yaml:"trustForwardedHeaders"`
	TicketKey             string `yaml:"ticketKey"`
}

// AccessLogConfig toggles HTTP access logging per server. Pointer fields let
// the YAML loader distinguish "unset" from an explicit false so the defaults
// can be applied without clobbering an operator's deliberate "off".
type AccessLogConfig struct {
	MCP   *bool `yaml:"mcp"`
	Admin *bool `yaml:"admin"`
}

// LoggingConfig controls the root slog handler.
//   - Level: debug | info | warn | error  (default: info)
//   - Format: json | text                  (default: json for aggregator-ready
//     deployments; local dev typically overrides via LOG_FORMAT=text in
//     agentsmith.env)
//   - Access: per-server access-log toggles, both default true.
//
// LOG_LEVEL and LOG_FORMAT environment variables override the YAML values at
// startup, so operators can bump verbosity without editing config.
type LoggingConfig struct {
	Level  string          `yaml:"level"`
	Format string          `yaml:"format"`
	Access AccessLogConfig `yaml:"access"`
}

// Config is the top-level agentsmith configuration.
type Config struct {
	ListenAddr string        `yaml:"listenAddr"`
	AdminAddr  string        `yaml:"adminAddr"`
	Path       string        `yaml:"path"`
	AuthMode   AuthMode      `yaml:"authMode"`
	OAuth      OAuthConfig   `yaml:"oauth"`
	Logging    LoggingConfig `yaml:"logging"`
	Targets    []Target      `yaml:"targets"`
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
	if err := applyLoggingDefaults(&cfg.Logging); err != nil {
		return nil, err
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

// applyLoggingDefaults fills in unset logging fields and validates the
// remaining values. It is called from Load after YAML unmarshalling.
func applyLoggingDefaults(l *LoggingConfig) error {
	if l.Level == "" {
		l.Level = "info"
	}
	switch l.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("logging.level: %q is not a valid value (expected debug, info, warn, or error)", l.Level)
	}
	if l.Format == "" {
		l.Format = "json"
	}
	if l.Format != "json" && l.Format != "text" {
		return fmt.Errorf("logging.format: %q is not a valid value (expected json or text)", l.Format)
	}
	if l.Access.MCP == nil {
		t := true
		l.Access.MCP = &t
	}
	if l.Access.Admin == nil {
		t := true
		l.Access.Admin = &t
	}
	return nil
}

// LoggingFromEnv returns a copy of l with Level and Format overridden by the
// LOG_LEVEL and LOG_FORMAT environment variables when set. Empty env values
// are ignored. Validation happens on the next caller (logging.New) so an
// invalid override surfaces a clear error rather than being silently dropped.
func LoggingFromEnv(l LoggingConfig) LoggingConfig {
	if v, ok := os.LookupEnv("LOG_LEVEL"); ok && v != "" {
		l.Level = v
	}
	if v, ok := os.LookupEnv("LOG_FORMAT"); ok && v != "" {
		l.Format = v
	}
	return l
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

// envVarRe matches ${VAR} placeholders whose names follow the conventional
// uppercase shell-env convention. Anything else (lowercase, hyphens, missing
// braces) is caught by anyEnvLikeRe below so we can return an explicit error
// instead of silently leaving the literal text in the YAML, which causes
// confusing downstream parse or auth failures.
var (
	envVarRe     = regexp.MustCompile(`\$\{([A-Z_][A-Z0-9_]*)\}`)
	anyEnvLikeRe = regexp.MustCompile(`\$\{([^}]*)\}`)
)

// expandEnv replaces ${VAR} occurrences with their environment value, erroring
// if any referenced variable is unset OR if a ${...} placeholder uses a name
// that doesn't match the canonical uppercase form. This avoids silently
// shipping a config with empty secrets or with literal ${...} text that the
// user thought would be expanded.
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
	// After expansion, anything ${...}-shaped left in the output is a name
	// the strict regex rejected. Flag it explicitly rather than letting it
	// surface as a confusing YAML or runtime error.
	if leftovers := anyEnvLikeRe.FindAllStringSubmatch(out, -1); len(leftovers) > 0 {
		names := make([]string, 0, len(leftovers))
		for _, m := range leftovers {
			names = append(names, m[1])
		}
		return "", fmt.Errorf("unsupported ${...} placeholder(s) in config: %v — env var names must match [A-Z_][A-Z0-9_]*", names)
	}
	return out, nil
}
