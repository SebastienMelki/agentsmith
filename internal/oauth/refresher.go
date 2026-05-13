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
//
// Pointers returned by Get are treated as immutable — callers that need to
// change a field MUST construct a new BackendConfig and pass it to Set,
// serializing concurrent updates via LockForUpdate. This avoids torn reads
// in the Refresher while a connect handler runs Dynamic Client Registration.
type Registry struct {
	mu sync.RWMutex
	m  map[string]*BackendConfig

	// updateMu protects the perBackend map; the per-backend mutexes themselves
	// are short-lived locks held across read-modify-write of one backend's cfg.
	updateMu   sync.Mutex
	perBackend map[string]*sync.Mutex
}

// NewRegistry returns an empty backend registry.
func NewRegistry() *Registry {
	return &Registry{
		m:          make(map[string]*BackendConfig),
		perBackend: make(map[string]*sync.Mutex),
	}
}

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

// LockForUpdate acquires a per-backend lock so a caller can perform a
// read-modify-write on the registered config without racing other Update
// callers for the same backend. The returned func must be called (typically
// via defer) to release the lock. Concurrent reads via Get continue to work;
// the lock only serializes Update callers among themselves.
func (r *Registry) LockForUpdate(name string) func() {
	r.updateMu.Lock()
	m, ok := r.perBackend[name]
	if !ok {
		m = &sync.Mutex{}
		r.perBackend[name] = m
	}
	r.updateMu.Unlock()
	m.Lock()
	return m.Unlock
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
