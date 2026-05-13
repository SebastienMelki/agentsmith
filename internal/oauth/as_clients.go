package oauth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"slices"
	"sync"
	"time"
)

// DCRClient is the per-client record produced by Dynamic Client Registration
// (RFC 7591) when an MCP client (Claude Code, Cursor, …) registers itself
// against agentsmith's own authorization server.
//
// All MCP clients we expect to see are public — PKCE-only, no client secret.
// We keep the record minimal: the redirect URIs the client may use and
// metadata that's useful for log triage.
type DCRClient struct {
	ID           string    `json:"client_id"`
	RedirectURIs []string  `json:"redirect_uris"`
	Name         string    `json:"client_name,omitempty"`
	IssuedAt     time.Time `json:"-"`
}

// ErrUnknownClient is returned by ClientStore.Lookup when a client_id is not
// registered. Handlers translate this to RFC 6749 §4.1.2.1 "invalid_client".
var ErrUnknownClient = errors.New("oauth: unknown client_id")

// ClientStore persists DCR registrations. The in-memory implementation is
// sufficient for v1 — clients re-register on restart, exactly like the
// upstream-side DCR the gateway already runs against backends.
type ClientStore struct {
	mu sync.RWMutex
	m  map[string]*DCRClient
}

// NewClientStore returns an empty in-memory client store.
func NewClientStore() *ClientStore {
	return &ClientStore{m: make(map[string]*DCRClient)}
}

// Register stores a new client and returns the issued record. The caller
// supplies the redirect URIs (already validated for shape); Register generates
// an opaque client_id and stamps IssuedAt.
func (s *ClientStore) Register(name string, redirectURIs []string) (*DCRClient, error) {
	if len(redirectURIs) == 0 {
		return nil, errors.New("oauth: at least one redirect_uri is required")
	}
	id, err := generateClientID()
	if err != nil {
		return nil, err
	}
	c := &DCRClient{
		ID:           id,
		Name:         name,
		RedirectURIs: append([]string(nil), redirectURIs...),
		IssuedAt:     time.Now().UTC(),
	}
	s.mu.Lock()
	s.m[id] = c
	s.mu.Unlock()
	return c, nil
}

// Lookup returns the client by id, or ErrUnknownClient.
func (s *ClientStore) Lookup(id string) (*DCRClient, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.m[id]
	if !ok {
		return nil, ErrUnknownClient
	}
	cp := *c
	cp.RedirectURIs = append([]string(nil), c.RedirectURIs...)
	return &cp, nil
}

// AllowsRedirect reports whether redirect is one of the URIs the client
// registered. OAuth requires exact match — no prefix or wildcard handling.
func (c *DCRClient) AllowsRedirect(redirect string) bool {
	return slices.Contains(c.RedirectURIs, redirect)
}

// generateClientID returns a fresh URL-safe identifier. The "as_" prefix marks
// it as gateway-issued (so it's distinguishable from upstream client_ids in
// logs); 32 hex chars is 128 bits — comfortable margin against guessing even
// without secrecy.
func generateClientID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "as_" + hex.EncodeToString(b), nil
}
