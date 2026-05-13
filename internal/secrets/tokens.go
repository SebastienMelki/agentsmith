// Package secrets stores OAuth tokens per (user, backend) and refreshes them
// silently when they near expiry. The exported types form the seam where a
// SQLite-backed implementation can replace MemoryTokenStore without touching
// any call site.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// refreshLeeway is how close to expiry we are willing to use an access token
// before refreshing. Slightly larger than typical network jitter so a call
// that takes a few hundred milliseconds will not hit a just-expired token.
const refreshLeeway = 60 * time.Second

// Tokens is the persisted OAuth state for one (user, backend) pair.
type Tokens struct {
	AccessToken  string    `json:"accessToken"`
	RefreshToken string    `json:"refreshToken"`
	TokenType    string    `json:"tokenType"`
	ExpiresAt    time.Time `json:"expiresAt"` // zero value means "never expires"
	Scopes       []string  `json:"scopes,omitempty"`
}

// Expired reports whether the access token is at or past its expiry. A zero
// ExpiresAt is treated as "never expires" (some providers issue long-lived
// tokens with no exp field).
func (t *Tokens) Expired() bool {
	if t.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().UTC().After(t.ExpiresAt)
}

// NeedsRefresh reports whether the access token is within refreshLeeway of
// expiry. Used by RefreshingTokenStore to refresh proactively.
func (t *Tokens) NeedsRefresh() bool {
	if t.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().UTC().Add(refreshLeeway).After(t.ExpiresAt)
}

// ErrNotFound is returned by TokenStore.Get when no tokens exist for the
// given (user, backend) pair. Callers should distinguish this from other
// errors so they can emit the "please connect" prompt.
var ErrNotFound = errors.New("secrets: tokens not found")

// TokenStore persists OAuth tokens. Implementations must be safe for
// concurrent use. The contract is intentionally CRUD-shaped — refresh logic
// lives in RefreshingTokenStore, which decorates an unrefreshing store.
type TokenStore interface {
	Get(userID, backend string) (*Tokens, error)
	Save(userID, backend string, t *Tokens) error
	Delete(userID, backend string) error
}

// MemoryTokenStore is an in-memory TokenStore. Lost on restart.
type MemoryTokenStore struct {
	mu sync.RWMutex
	m  map[string]*Tokens
}

// NewMemoryTokenStore returns an empty in-memory token store.
func NewMemoryTokenStore() *MemoryTokenStore {
	return &MemoryTokenStore{m: make(map[string]*Tokens)}
}

func tokenKey(userID, backend string) string { return userID + "\x00" + backend }

// Get implements TokenStore.
func (s *MemoryTokenStore) Get(userID, backend string) (*Tokens, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.m[tokenKey(userID, backend)]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *t
	if len(t.Scopes) > 0 {
		cp.Scopes = append([]string(nil), t.Scopes...)
	}
	return &cp, nil
}

// Save implements TokenStore. nil t is rejected so callers cannot
// accidentally erase tokens by passing a zero pointer.
func (s *MemoryTokenStore) Save(userID, backend string, t *Tokens) error {
	if t == nil {
		return errors.New("secrets: refusing to Save nil tokens — use Delete")
	}
	cp := *t
	if len(t.Scopes) > 0 {
		cp.Scopes = append([]string(nil), t.Scopes...)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[tokenKey(userID, backend)] = &cp
	return nil
}

// Delete implements TokenStore.
func (s *MemoryTokenStore) Delete(userID, backend string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, tokenKey(userID, backend))
	return nil
}

// Refresher swaps a refresh token for a fresh Tokens value. The
// internal/oauth package implements this against an upstream's token endpoint;
// the interface lives here so we can wire a fake in tests without an import
// cycle.
type Refresher interface {
	Refresh(ctx context.Context, backend string, refreshToken string) (*Tokens, error)
}

// RefreshingTokenStore decorates a TokenStore with auto-refresh: callers see
// an access token that is always at least refreshLeeway away from expiring,
// and the refreshed token (including a possibly-rotated refresh_token) is
// persisted back to the underlying store. Save and Delete pass through.
type RefreshingTokenStore struct {
	inner     TokenStore
	refresher Refresher

	// One refresh per (user, backend) is in flight at a time so concurrent
	// callers do not stampede the upstream token endpoint. Entries are
	// reference-counted and deleted when the last waiter releases them so
	// the map does not grow unbounded over the gateway's lifetime.
	mu       sync.Mutex
	inflight map[string]*refreshLock
}

// refreshLock is a per-(user, backend) mutex with a waiter count so we can
// drop the entry when the last caller releases it.
type refreshLock struct {
	mu      sync.Mutex
	waiters int
}

// NewRefreshingTokenStore wraps inner with auto-refresh logic backed by r.
// If r is nil the store behaves identically to inner.
func NewRefreshingTokenStore(inner TokenStore, r Refresher) *RefreshingTokenStore {
	return &RefreshingTokenStore{
		inner:     inner,
		refresher: r,
		inflight:  make(map[string]*refreshLock),
	}
}

// Get returns the stored tokens, transparently refreshing them when they are
// within refreshLeeway of expiry. If the underlying tokens have no refresh
// token, the existing access token is returned as-is even when expired —
// callers can react to a 401 from the upstream on their own.
func (s *RefreshingTokenStore) Get(ctx context.Context, userID, backend string) (*Tokens, error) {
	tok, err := s.inner.Get(userID, backend)
	if err != nil {
		return nil, err
	}
	if !tok.NeedsRefresh() || tok.RefreshToken == "" || s.refresher == nil {
		return tok, nil
	}

	k := tokenKey(userID, backend)
	lock := s.acquireRefreshLock(k)
	defer s.releaseRefreshLock(k)
	lock.Lock()
	defer lock.Unlock()

	// Re-check after acquiring the lock: another goroutine may have refreshed
	// already.
	tok, err = s.inner.Get(userID, backend)
	if err != nil {
		return nil, err
	}
	if !tok.NeedsRefresh() {
		return tok, nil
	}

	slog.Debug("refreshing token", "backend", backend, "user_id", userID)
	fresh, err := s.refresher.Refresh(ctx, backend, tok.RefreshToken)
	if err != nil {
		slog.Warn("token refresh failed", "backend", backend, "user_id", userID, "error", err)
		return nil, fmt.Errorf("secrets: refresh %s for %s: %w", backend, userID, err)
	}
	// Carry forward the refresh token if the upstream did not return a new
	// one (some providers omit it on refresh responses).
	if fresh.RefreshToken == "" {
		fresh.RefreshToken = tok.RefreshToken
	}
	if err := s.inner.Save(userID, backend, fresh); err != nil {
		return nil, fmt.Errorf("secrets: persist refreshed tokens: %w", err)
	}
	var expiresInS int64
	if !fresh.ExpiresAt.IsZero() {
		expiresInS = int64(time.Until(fresh.ExpiresAt).Seconds())
	}
	slog.Info("token refreshed", "backend", backend, "user_id", userID, "expires_in_s", expiresInS)
	return fresh, nil
}

// Save passes through to the underlying store.
func (s *RefreshingTokenStore) Save(userID, backend string, t *Tokens) error {
	return s.inner.Save(userID, backend, t)
}

// Delete passes through to the underlying store.
func (s *RefreshingTokenStore) Delete(userID, backend string) error {
	return s.inner.Delete(userID, backend)
}

// acquireRefreshLock returns the per-(user, backend) refresh mutex, creating
// it on first use, and bumps its waiter count. Callers MUST pair this with a
// release call so the entry can be reclaimed when idle. The returned mutex
// is held only for the duration of a refresh; never held alongside the
// underlying store's lock.
func (s *RefreshingTokenStore) acquireRefreshLock(k string) *sync.Mutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	rl, ok := s.inflight[k]
	if !ok {
		rl = &refreshLock{}
		s.inflight[k] = rl
	}
	rl.waiters++
	return &rl.mu
}

// releaseRefreshLock decrements the waiter count for k and deletes the entry
// when no goroutines are waiting on or holding it. Pair with acquireRefreshLock.
func (s *RefreshingTokenStore) releaseRefreshLock(k string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rl, ok := s.inflight[k]
	if !ok {
		return
	}
	rl.waiters--
	if rl.waiters <= 0 {
		delete(s.inflight, k)
	}
}
