package identity

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/sebastienmelki/agentsmith/internal/config"
	"github.com/sebastienmelki/agentsmith/internal/logging"
)

// Middleware returns an HTTP middleware that resolves the caller's identity
// and attaches it to the request context via WithUser.
//
// In config.ModeProtected: requires Authorization: Bearer <api_key>. Missing
// or unknown keys produce a 401 with a WWW-Authenticate header — clients that
// implement the MCP authorization spec surface this to the user.
//
// In config.ModeUnprotected: attaches a fixed *User keyed by DefaultUserID
// and passes through. Tool handlers read the same context key in both modes
// so the rest of the code does not branch on auth mode.
func Middleware(mode config.AuthMode, store Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, reason, ok := resolveUser(mode, store, r)
			if !ok {
				logging.FromContext(r.Context()).Warn("auth rejected",
					"reason", reason,
					"remote_addr", r.RemoteAddr,
					"path", r.URL.Path,
				)
				writeUnauthorized(w, r)
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
// "missing_bearer" / "invalid_bearer" / "unknown_key" on failure and empty on
// success — used by Middleware to attribute 401s without re-parsing the
// header.
func resolveUser(mode config.AuthMode, store Store, r *http.Request) (*User, string, bool) {
	if mode != config.ModeProtected {
		return defaultUser(), "", true
	}
	hdr := r.Header.Get("Authorization")
	if hdr == "" {
		return nil, "missing_bearer", false
	}
	key := bearerToken(hdr)
	if key == "" {
		return nil, "invalid_bearer", false
	}
	u, err := store.Lookup(key)
	if err != nil {
		return nil, "unknown_key", false
	}
	return u, "", true
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

// writeUnauthorized emits the MCP-spec-aligned 401 response. WWW-Authenticate
// names the realm so clients that implement the authorization spec can
// trigger their connect flow. Body is a small JSON error so non-MCP callers
// still get something readable.
func writeUnauthorized(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="agentsmith", error="invalid_token"`)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             "unauthorized",
		"error_description": "missing or invalid api key — set Authorization: Bearer <api_key>",
	})
}
