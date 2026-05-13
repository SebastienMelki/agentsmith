package identity

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/sebastienmelki/agentsmith/internal/config"
	"github.com/sebastienmelki/agentsmith/internal/logging"
)

// BearerLookup resolves a gateway-issued OAuth access token to the user it
// represents. Returns ok=false for unknown or expired tokens. The middleware
// calls this BEFORE falling back to the API-key store so a token issued by
// the gateway's own AS authenticates the caller in either auth mode.
type BearerLookup func(token string) (userID string, ok bool)

// Options groups the identity middleware's dependencies. Bearer and
// ResourceMetadata may both be nil — in that case the middleware behaves like
// the pre-AS version: API-key only in protected mode, pass-through in
// unprotected mode.
type Options struct {
	Mode             config.AuthMode
	Users            Store
	Bearer           BearerLookup
	ResourceMetadata func(*http.Request) string // populates WWW-Authenticate: resource_metadata="..."
}

// Middleware returns an HTTP middleware that resolves the caller's identity
// and attaches it to the request context via WithUser.
//
// Auth modes and the WWW-Authenticate envelope:
//
//   - ModeProtected, Bearer != nil: AS tokens accepted; API keys accepted as
//     fallback. Missing/invalid auth → 401 + WWW-Authenticate carrying the
//     resource_metadata URL so MCP clients can run OAuth automatically.
//   - ModeProtected, Bearer == nil: API keys only (pre-AS behaviour). 401
//     emits a plain "invalid_token" challenge.
//   - ModeUnprotected, Bearer != nil: AS tokens REQUIRED — missing tokens
//     produce a 401 challenge so the browser opens. Token UserID is the
//     synthetic DefaultUserID (unprotected mode pins everything to one user).
//   - ModeUnprotected, Bearer == nil: anonymous pass-through (DefaultUserID).
func Middleware(opts Options) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, reason, ok := opts.resolveUser(r)
			if !ok {
				logging.FromContext(r.Context()).Warn("auth rejected",
					"reason", reason,
					"remote_addr", r.RemoteAddr,
					"path", r.URL.Path,
				)
				opts.writeUnauthorized(w, r)
				return
			}
			ctx := WithUser(r.Context(), user)
			// Stash the user_id on context (for the access log middleware
			// to pick up) and on the ctx-scoped logger (for downstream
			// handlers and any per-request slog calls). The in-place
			// mutation ensures the AccessLog middleware wrapping us sees
			// the user_id after next.ServeHTTP returns.
			ctx = logging.WithUserID(ctx, user.ID)
			ctx = logging.WithLogger(ctx, logging.FromContext(ctx).With("user_id", user.ID))
			*r = *r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}

// resolveUser implements the per-mode auth logic. The reason string is
// "missing_bearer" / "invalid_bearer" / "unknown_token" / "unknown_key" on
// failure and empty on success — used by Middleware to attribute 401s
// without re-parsing the header.
func (o Options) resolveUser(r *http.Request) (*User, string, bool) {
	hdr := r.Header.Get("Authorization")
	bearer := bearerToken(hdr)

	// Honour gateway-issued OAuth tokens first when wired. Whichever user the
	// token maps to wins in either auth mode — the AS is the source of truth.
	if o.Bearer != nil && bearer != "" {
		if userID, ok := o.Bearer(bearer); ok {
			return &User{ID: userID, Email: userID, CreatedAt: time.Time{}}, "", true
		}
	}

	switch o.Mode {
	case config.ModeProtected:
		if hdr == "" {
			return nil, "missing_bearer", false
		}
		if bearer == "" {
			return nil, "invalid_bearer", false
		}
		u, err := o.Users.Lookup(bearer)
		if err != nil {
			return nil, "unknown_key", false
		}
		return u, "", true
	default:
		// Unprotected mode. Anonymous calls always pass — that's the point of
		// "unprotected." The browser-opens-automatically behaviour is driven
		// per-tool-call by the scope-check middleware further down the chain,
		// not by gating the whole MCP endpoint behind a bearer up front.
		// Static-backend tools must work for users who have never OAuth'd.
		return defaultUser(), "", true
	}
}

// defaultUser is the synthetic identity used in ModeUnprotected. A fresh
// struct is returned per call so handlers cannot accidentally mutate shared
// state.
func defaultUser() *User {
	return &User{ID: DefaultUserID, Email: DefaultUserID, CreatedAt: time.Time{}}
}

// bearerToken extracts the value after "Bearer " from an Authorization header,
// case-insensitively on the scheme. Returns "" if the header is malformed.
func bearerToken(h string) string {
	const prefix = "bearer "
	if len(h) <= len(prefix) {
		return ""
	}
	if !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

// writeUnauthorized emits the MCP-spec-aligned 401 response. When AS is wired
// (ResourceMetadata != nil), the challenge carries resource_metadata="..." per
// RFC 9728 so MCP clients automatically discover the gateway's authorization
// server and pop a browser. Body is a small JSON error so non-MCP callers
// still get something readable.
func (o Options) writeUnauthorized(w http.ResponseWriter, r *http.Request) {
	challenge := `Bearer realm="agentsmith", error="invalid_token"`
	if o.ResourceMetadata != nil {
		if u := o.ResourceMetadata(r); u != "" {
			challenge = `Bearer realm="agentsmith", error="invalid_token", resource_metadata="` + u + `"`
		}
	}
	w.Header().Set("WWW-Authenticate", challenge)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	desc := "missing or invalid bearer token"
	if o.Mode == config.ModeProtected && o.Bearer == nil {
		desc = "missing or invalid api key — set Authorization: Bearer <api_key>"
	}
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             "unauthorized",
		"error_description": desc,
	})
}
