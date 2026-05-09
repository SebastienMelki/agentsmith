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

// Target describes one MCP backend that agentsmith federates.
type Target struct {
	Name    string            `yaml:"name"`
	URL     string            `yaml:"url"`
	Headers map[string]string `yaml:"headers"`
}

// Config is the top-level agentsmith configuration.
type Config struct {
	ListenAddr string   `yaml:"listenAddr"`
	Path       string   `yaml:"path"`
	Targets    []Target `yaml:"targets"`
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
	if len(cfg.Targets) == 0 {
		return nil, errors.New("at least one target is required")
	}
	for i, t := range cfg.Targets {
		if t.Name == "" || t.URL == "" {
			return nil, fmt.Errorf("targets[%d]: name and url are required", i)
		}
	}
	return &cfg, nil
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
