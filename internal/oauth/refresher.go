package oauth

import (
	"context"
	"fmt"
	"sync"

	"github.com/sebastienmelki/agentsmith/internal/secrets"
)

// BackendConfig is everything the Refresher and Connect handler need to talk
// to one upstream's authorization server.
type BackendConfig struct {
	Name         string
	ClientID     string
	ClientSecret string
	Scopes       []string
	Endpoints    *Endpoints
}

// Registry holds per-backend OAuth config and is used by both the Refresher
// and the connect/callback handlers. It is safe for concurrent reads after
// construction; mutate via Set.
type Registry struct {
	mu sync.RWMutex
	m  map[string]*BackendConfig
}

// NewRegistry returns an empty backend registry.
func NewRegistry() *Registry { return &Registry{m: make(map[string]*BackendConfig)} }

// Set registers or replaces a backend's OAuth config.
func (r *Registry) Set(cfg *BackendConfig) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[cfg.Name] = cfg
}

// Get returns the config for a backend, or false if unknown.
func (r *Registry) Get(name string) (*BackendConfig, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.m[name]
	return c, ok
}

// Refresher implements secrets.Refresher against a Registry, posting to the
// per-backend token endpoint with the configured client credentials.
type Refresher struct {
	reg *Registry
}

// NewRefresher returns a secrets.Refresher that resolves per-backend config
// from the registry. Returned Refresher is safe for concurrent use.
func NewRefresher(reg *Registry) *Refresher { return &Refresher{reg: reg} }

// Refresh implements secrets.Refresher.
func (r *Refresher) Refresh(ctx context.Context, backend, refreshToken string) (*secrets.Tokens, error) {
	cfg, ok := r.reg.Get(backend)
	if !ok {
		return nil, fmt.Errorf("oauth: no config registered for backend %q", backend)
	}
	if err := cfg.Endpoints.Validate(); err != nil {
		return nil, err
	}
	return Refresh(ctx, cfg.Endpoints, cfg.ClientID, cfg.ClientSecret, refreshToken)
}
