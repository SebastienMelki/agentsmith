package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

// authorizationCode is the one-shot grant minted at the end of /oauth/authorize
// and traded at /oauth/token. It binds the issued code to the original
// authorization request so a stolen code cannot be redeemed by a different
// client or against a different redirect_uri.
type authorizationCode struct {
	Code                string
	ClientID            string
	UserID              string
	RedirectURI         string
	Scopes              []string
	CodeChallenge       string
	CodeChallengeMethod string
	Expires             time.Time
}

// CodeStore is the in-memory map of unredeemed authorization codes. Codes are
// single-use: take() removes them on the way out.
type CodeStore struct {
	mu sync.Mutex
	m  map[string]*authorizationCode
}

// NewCodeStore returns an empty in-memory authorization-code store.
func NewCodeStore() *CodeStore { return &CodeStore{m: make(map[string]*authorizationCode)} }

// put stores a freshly minted code. The in-memory map is pruned on each write
// — cheap because it only ever holds codes that have been issued but not yet
// redeemed (single-digit count in practice).
func (s *CodeStore) put(c *authorizationCode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	s.m[c.Code] = c
}

// take returns and deletes the entry for code, or nil if missing or expired.
// Used exactly once per code at /oauth/token.
func (s *CodeStore) take(code string) *authorizationCode {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.m[code]
	if !ok {
		return nil
	}
	delete(s.m, code)
	if time.Now().After(c.Expires) {
		return nil
	}
	return c
}

func (s *CodeStore) pruneLocked() {
	now := time.Now()
	for k, v := range s.m {
		if now.After(v.Expires) {
			delete(s.m, k)
		}
	}
}

// IssuedToken is the gateway-issued bearer token tracked server-side. We use
// opaque tokens (not JWTs) so revocation is O(1) and the access token cannot
// be parsed by callers to enumerate scopes — they have to ask the gateway.
type IssuedToken struct {
	AccessToken  string
	RefreshToken string
	ClientID     string
	UserID       string
	Scopes       []string
	IssuedAt     time.Time
	Expires      time.Time
}

// accessTokenTTL is how long a gateway-issued access token is valid. Refresh
// tokens carry no inherent TTL; we revoke them on /oauth/token rotation
// instead so a leaked refresh token can be detected by the legitimate client
// when its rotated copy stops working.
const accessTokenTTL = 24 * time.Hour

// TokenStore persists issued tokens for the gateway's own AS. Independent of
// upstream tokens (secrets.TokenStore): this store is keyed by gateway access
// token, that one is keyed by (user, backend).
type TokenStore struct {
	mu          sync.RWMutex
	byAccess    map[string]*IssuedToken
	byRefresh   map[string]*IssuedToken
}

// NewASTokenStore returns an empty in-memory token store.
func NewASTokenStore() *TokenStore {
	return &TokenStore{
		byAccess:  make(map[string]*IssuedToken),
		byRefresh: make(map[string]*IssuedToken),
	}
}

// ErrTokenNotFound is returned by Lookup when the bearer is unknown.
var ErrTokenNotFound = errors.New("oauth: token not found")

// ErrTokenExpired is returned by Lookup when the bearer is known but past
// its expiry. The caller surfaces this as an "invalid_token" 401 — the same
// shape Lookup-not-found would emit, but logged differently.
var ErrTokenExpired = errors.New("oauth: token expired")

// Issue mints a new access + refresh token bound to the given identity and
// scopes, stores them, and returns the resulting record.
func (s *TokenStore) Issue(clientID, userID string, scopes []string) (*IssuedToken, error) {
	access, err := randURLSafe(32)
	if err != nil {
		return nil, err
	}
	refresh, err := randURLSafe(32)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	t := &IssuedToken{
		AccessToken:  access,
		RefreshToken: refresh,
		ClientID:     clientID,
		UserID:       userID,
		Scopes:       append([]string(nil), scopes...),
		IssuedAt:     now,
		Expires:      now.Add(accessTokenTTL),
	}
	s.mu.Lock()
	s.byAccess[access] = t
	s.byRefresh[refresh] = t
	s.mu.Unlock()
	return t, nil
}

// Lookup returns the token record for an access token, or an error if the
// token is unknown or expired. The returned pointer is a copy — callers may
// not mutate it.
func (s *TokenStore) Lookup(accessToken string) (*IssuedToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.byAccess[accessToken]
	if !ok {
		return nil, ErrTokenNotFound
	}
	if time.Now().UTC().After(t.Expires) {
		return nil, ErrTokenExpired
	}
	cp := *t
	cp.Scopes = append([]string(nil), t.Scopes...)
	return &cp, nil
}

// Rotate exchanges a refresh token for a fresh access+refresh pair, revoking
// the old pair. Returns ErrTokenNotFound if the refresh token is unknown.
// Scopes are carried forward verbatim — narrowing happens at /oauth/authorize,
// not at refresh.
func (s *TokenStore) Rotate(refreshToken string) (*IssuedToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, ok := s.byRefresh[refreshToken]
	if !ok {
		return nil, ErrTokenNotFound
	}
	delete(s.byRefresh, refreshToken)
	delete(s.byAccess, prev.AccessToken)
	access, err := randURLSafe(32)
	if err != nil {
		return nil, err
	}
	refresh, err := randURLSafe(32)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	t := &IssuedToken{
		AccessToken:  access,
		RefreshToken: refresh,
		ClientID:     prev.ClientID,
		UserID:       prev.UserID,
		Scopes:       append([]string(nil), prev.Scopes...),
		IssuedAt:     now,
		Expires:      now.Add(accessTokenTTL),
	}
	s.byAccess[access] = t
	s.byRefresh[refresh] = t
	return t, nil
}

// VerifyPKCE checks that codeVerifier hashes to challenge under the named
// method. Only S256 is supported — plain is allowed by the spec but PKCE
// without S256 defeats the point and the MCP spec mandates S256.
func VerifyPKCE(codeVerifier, challenge, method string) error {
	if method != "S256" {
		return errors.New("oauth: unsupported code_challenge_method (require S256)")
	}
	sum := sha256.Sum256([]byte(codeVerifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if want != challenge {
		return errors.New("oauth: code_verifier does not match code_challenge")
	}
	return nil
}

