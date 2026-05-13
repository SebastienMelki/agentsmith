package oauth

import (
	"sync"
	"time"
)

// authzSession is the in-flight authorization request the gateway is driving
// on behalf of an MCP client. It captures the original /oauth/authorize
// parameters so we can return a valid code to the client at the very end, and
// the per-backend chaining state so we know which upstream OAuth to drive
// next after each callback.
//
// One session is created per call to /oauth/authorize and lives until it
// completes (code minted), is abandoned (user closes the browser tab), or
// times out (sessionTTL). Sessions are keyed by an opaque server-side ID we
// thread through each upstream callback via the per-backend stateEntry.
type authzSession struct {
	ID string

	// Client identity and original request parameters. ClientState is the
	// value the MCP client supplied; we echo it verbatim on the final
	// redirect so the client can correlate this response with its request.
	ClientID            string
	ClientRedirectURI   string
	ClientState         string
	CodeChallenge       string
	CodeChallengeMethod string
	ResourceIndicator   string // RFC 8707 resource value, echoed back

	// UserID is the authenticated user driving the flow. In unprotected mode
	// this is identity.DefaultUserID; protected mode resolves it from a
	// session cookie (future work).
	UserID string

	// Scopes is the full set of backend scopes requested at /authorize. Pending
	// is the subset that still needs an upstream OAuth round-trip; Granted is
	// what's done. We move scopes from Pending to Granted as upstream callbacks
	// arrive; when Pending is empty the session is ready to mint a code.
	Scopes  []string
	Pending []string
	Granted []string

	Expires time.Time
}

// sessionTTL bounds how long a single multi-backend authorization can run. 15
// minutes is generous — covers a user dropping into 1Password for credentials
// or completing MFA — but short enough that abandoned sessions don't pile up.
const sessionTTL = 15 * time.Minute

// SessionStore is an in-memory map of in-flight authorizations.
type SessionStore struct {
	mu sync.Mutex
	m  map[string]*authzSession
}

// NewSessionStore returns an empty in-memory authorization-session store.
func NewSessionStore() *SessionStore {
	return &SessionStore{m: make(map[string]*authzSession)}
}

// create stores a fresh session and returns its server-generated ID. Caller
// supplies the populated session (sans ID); we mint one, stamp Expires, and
// stash a copy.
func (s *SessionStore) create(sess *authzSession) (string, error) {
	id, err := randURLSafe(24)
	if err != nil {
		return "", err
	}
	sess.ID = id
	sess.Expires = time.Now().Add(sessionTTL)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	s.m[id] = sess
	return id, nil
}

// remove drops the session by ID. Called when a session completes (code
// minted) so the map doesn't retain finished sessions.
func (s *SessionStore) remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, id)
}

// markGranted moves one scope from Pending to Granted on the named session
// and returns the updated session. Returns nil if the session is unknown.
func (s *SessionStore) markGranted(id, scope string) *authzSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[id]
	if !ok {
		return nil
	}
	for i, p := range sess.Pending {
		if p == scope {
			sess.Pending = append(sess.Pending[:i], sess.Pending[i+1:]...)
			break
		}
	}
	sess.Granted = append(sess.Granted, scope)
	return sess
}

func (s *SessionStore) pruneLocked() {
	now := time.Now()
	for k, v := range s.m {
		if now.After(v.Expires) {
			delete(s.m, k)
		}
	}
}
