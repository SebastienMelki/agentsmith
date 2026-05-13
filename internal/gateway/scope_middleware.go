package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/sebastienmelki/agentsmith/internal/config"
	"github.com/sebastienmelki/agentsmith/internal/secrets"
)

// maxRPCBodyBytes caps how much we buffer when sniffing JSON-RPC bodies.
// Larger payloads are passed through unread (and a worst-case malicious
// payload still can't make us miss a tool-call check because tools/call
// arguments fit comfortably below this).
const maxRPCBodyBytes = 1 << 20 // 1 MiB

// ScopeMiddleware returns an HTTP middleware that enforces per-backend OAuth
// at the moment a tool is invoked, not at connect time. JSON-RPC requests are
// inspected: when the method is tools/call and the target tool belongs to an
// OAuth-typed backend that has no upstream tokens for the calling user, we
// short-circuit with an RFC 6750 §3.1 "insufficient_scope" 401 carrying the
// WWW-Authenticate challenge MCP clients use to open a browser.
//
// resourceMetadataURL builds the absolute URL to embed in
// WWW-Authenticate: resource_metadata="...". A nil builder is treated as
// empty — the 401 will still emit a usable challenge, just without the
// metadata pointer (clients can fall back to error="insufficient_scope" alone).
//
// The middleware never blocks tools/list, initialize, prompts/*, resources/*,
// or static-backend tools. Bodies that aren't valid JSON-RPC, or that are
// batches, fall through unmodified — keeping the spec edges out of the
// happy-path policy decision.
func (g *Gateway) ScopeMiddleware(resourceMetadataURL func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Cheap exits: anything that isn't a POST with a body can skip
			// the sniff. MCP's streamable HTTP transport uses POST for
			// requests; everything else is server-pushed events or session
			// management we have no policy on.
			if r.Method != http.MethodPost || r.Body == nil {
				next.ServeHTTP(w, r)
				return
			}
			buf, err := io.ReadAll(io.LimitReader(r.Body, maxRPCBodyBytes))
			_ = r.Body.Close()
			// Restore the body for the inner handler regardless of what we
			// decide — we are a transparent middleware on the happy path.
			r.Body = io.NopCloser(bytes.NewReader(buf))
			if err != nil {
				// Read error — let the inner handler see the body it can and
				// surface whatever the SDK chooses to return.
				next.ServeHTTP(w, r)
				return
			}

			backend, ok := g.toolCallBackend(buf)
			if !ok {
				next.ServeHTTP(w, r)
				return
			}
			if !g.backendNeedsAuthFor(backend, r) {
				next.ServeHTTP(w, r)
				return
			}

			// User has no tokens for this OAuth backend — return the
			// insufficient_scope challenge so a spec-compliant MCP client
			// opens the browser for exactly this backend's scope.
			scope := backend + ":*"
			challenge := `Bearer error="insufficient_scope", scope="` + scope + `"`
			if resourceMetadataURL != nil {
				if u := resourceMetadataURL(r); u != "" {
					challenge += `, resource_metadata="` + u + `"`
				}
			}
			w.Header().Set("WWW-Authenticate", challenge)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":             "insufficient_scope",
				"error_description": "backend " + backend + " requires user authorization — complete the OAuth flow to continue",
				"scope":             scope,
			})
			slog.Info("scope challenge issued",
				"backend", backend,
				"user_id", userIDFromContext(r.Context()),
				"remote_addr", r.RemoteAddr,
			)
		})
	}
}

// toolCallBackend inspects a JSON-RPC body and returns the backend portion of
// a "<backend>__<tool>" name when the body is a single tools/call invocation.
// Anything else — initialize, tools/list, malformed JSON, batches, names
// without the separator — returns ok=false so the caller passes through.
func (g *Gateway) toolCallBackend(body []byte) (string, bool) {
	if len(body) == 0 {
		return "", false
	}
	// Cheap pre-filter: bail before unmarshalling for obvious non-matches.
	if !bytes.Contains(body, []byte(`"tools/call"`)) {
		return "", false
	}
	var msg struct {
		Method string `json:"method"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	if err := json.Unmarshal(body, &msg); err != nil {
		return "", false
	}
	if msg.Method != "tools/call" {
		return "", false
	}
	before, _, ok := strings.Cut(msg.Params.Name, namespaceSep)
	if !ok || before == "" {
		return "", false
	}
	return before, true
}

// backendNeedsAuthFor returns true when calling tools on backend would
// require the caller to complete an upstream OAuth flow they have not yet
// completed. Static-typed backends, unknown backends (let the SDK 404 them),
// and OAuth backends with valid tokens on file all return false.
func (g *Gateway) backendNeedsAuthFor(backend string, r *http.Request) bool {
	b := g.backendByName(backend)
	if b == nil {
		return false
	}
	if b.authType != config.AuthTypeOAuth {
		return false
	}
	userID := userIDFromContext(r.Context())
	if userID == "" {
		// No user resolved — identity middleware misconfigured. Let the inner
		// handler surface that as a tool error; the scope middleware should
		// not double-fault into 401 here.
		return false
	}
	if g.deps.Tokens == nil {
		return true
	}
	_, err := g.deps.Tokens.Get(r.Context(), userID, backend)
	if err == nil {
		return false
	}
	// Only treat ErrNotFound as "needs auth." A transport/refresh error means
	// the tokens exist but couldn't be refreshed; surface that as a tool
	// error rather than re-prompting OAuth (re-prompting wouldn't help).
	return secretsErrIsNotFound(err)
}

// secretsErrIsNotFound reports whether err is (or wraps) the upstream
// secrets.ErrNotFound sentinel. RefreshingTokenStore wraps the underlying
// error with fmt.Errorf("…: %w", err), so errors.Is is the right test.
// Other error shapes (transport failures, decode errors) deliberately do not
// trigger the OAuth challenge — re-prompting consent wouldn't help.
func secretsErrIsNotFound(err error) bool {
	return errors.Is(err, secrets.ErrNotFound)
}
