// Package identity owns the gateway's notion of "who is calling". It exposes
// a User registry behind a Store interface (in-memory implementation for v1,
// SQLite-backed implementation can drop in later without touching call sites)
// and an HTTP middleware that resolves an Authorization: Bearer <api_key>
// header into a *User on the request context.
package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// DefaultUserID is the synthetic user attached to every request in
// ModeUnprotected. The gateway pins all OAuth tokens to this ID when the
// operator has not opted into per-user API keys.
const DefaultUserID = "default"

// User is the minimal record we keep about a person calling the gateway. The
// admin UI surfaces this; the gateway uses ID as the key for OAuth tokens.
type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"createdAt"`
}

// ErrNotFound is returned by Store.Lookup when no user matches the given key.
var ErrNotFound = errors.New("identity: user not found")

// Store persists users and lets the middleware resolve an API key back to a
// user. Implementations must be safe for concurrent use.
type Store interface {
	// Lookup returns the user owning the given plaintext API key, or
	// ErrNotFound if no match. Keys are compared after hashing.
	Lookup(apiKey string) (*User, error)
	// Create registers a new user keyed by email and returns (user, plaintext
	// api key). The plaintext key is only visible at this moment; the store
	// keeps a hash. Calling Create with an existing email returns an error.
	Create(email string) (*User, string, error)
	// List returns all users sorted by creation time (oldest first).
	List() []User
	// Delete removes the user with the given id. Idempotent — returns nil if
	// the user does not exist.
	Delete(id string) error
}

// MemoryStore is an in-memory Store implementation. State is lost on process
// restart; ship a persistent implementation behind the same interface for prod.
type MemoryStore struct {
	mu     sync.RWMutex
	byID   map[string]*User
	byHash map[string]string // sha256(apiKey) hex -> user ID
}

// NewMemoryStore returns an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		byID:   make(map[string]*User),
		byHash: make(map[string]string),
	}
}

// Lookup implements Store.
func (s *MemoryStore) Lookup(apiKey string) (*User, error) {
	if apiKey == "" {
		return nil, ErrNotFound
	}
	h := hashKey(apiKey)
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byHash[h]
	if !ok {
		return nil, ErrNotFound
	}
	u := s.byID[id]
	if u == nil {
		return nil, ErrNotFound
	}
	cp := *u
	return &cp, nil
}

// Create implements Store. The DefaultUserID is reserved.
func (s *MemoryStore) Create(email string) (*User, string, error) {
	if email == "" {
		return nil, "", errors.New("identity: email is required")
	}
	if email == DefaultUserID {
		return nil, "", fmt.Errorf("identity: %q is a reserved user id", DefaultUserID)
	}
	key, err := generateAPIKey()
	if err != nil {
		return nil, "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.byID[email]; exists {
		return nil, "", fmt.Errorf("identity: user %q already exists", email)
	}
	u := &User{ID: email, Email: email, CreatedAt: time.Now().UTC()}
	s.byID[email] = u
	s.byHash[hashKey(key)] = email
	cp := *u
	return &cp, key, nil
}

// List implements Store.
func (s *MemoryStore) List() []User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]User, 0, len(s.byID))
	for _, u := range s.byID {
		out = append(out, *u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// Delete implements Store.
func (s *MemoryStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[id]; !ok {
		return nil
	}
	delete(s.byID, id)
	for h, uid := range s.byHash {
		if uid == id {
			delete(s.byHash, h)
		}
	}
	return nil
}

// generateAPIKey returns a fresh, opaque key. The "sk_" prefix mirrors the
// convention most providers use so it is recognisable in logs/screenshots.
func generateAPIKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("identity: generate api key: %w", err)
	}
	return "sk_" + hex.EncodeToString(b), nil
}

// hashKey returns the hex sha256 of an API key. We store only the hash so a
// dump of the in-memory store (or, later, the SQLite file) does not leak
// usable credentials.
func hashKey(apiKey string) string {
	sum := sha256.Sum256([]byte(apiKey))
	return hex.EncodeToString(sum[:])
}

type ctxKey struct{}

// WithUser returns a child context carrying the given user. Used by the
// middleware and by tests that want to bypass the HTTP layer.
func WithUser(ctx context.Context, u *User) context.Context {
	return context.WithValue(ctx, ctxKey{}, u)
}

// FromContext returns the *User attached by the middleware, or nil if none.
func FromContext(ctx context.Context) *User {
	u, _ := ctx.Value(ctxKey{}).(*User)
	return u
}
