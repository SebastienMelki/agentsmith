package oauth

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sebastienmelki/agentsmith/internal/secrets"
)

// ConnectPath is the URL path the gateway listens on for browser-initiated
// OAuth flows. The user lands here with a signed ticket; we redirect to the
// upstream authorization server.
const ConnectPath = "/oauth/connect/"

// CallbackPath is where the upstream sends the user back after they approve.
// The handler exchanges the code for tokens and persists them.
const CallbackPath = "/oauth/callback/"

// stateEntry is the per-flow data we stash between /oauth/connect and
// /oauth/callback. State tokens are single-use; entries are deleted on
// retrieval and prune themselves after a TTL.
type stateEntry struct {
	UserID       string
	Backend      string
	PKCEVerifier string
	RedirectURI  string
	Expires      time.Time
}

// stateStore is an in-memory single-use map keyed by state value.
type stateStore struct {
	mu sync.Mutex
	m  map[string]*stateEntry
}

func newStateStore() *stateStore { return &stateStore{m: make(map[string]*stateEntry)} }

func (s *stateStore) put(state string, e *stateEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	s.m[state] = e
}

func (s *stateStore) take(state string) *stateEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[state]
	if !ok {
		return nil
	}
	delete(s.m, state)
	if time.Now().After(e.Expires) {
		return nil
	}
	return e
}

// pruneLocked drops expired entries. Cheap because the map is small (one
// entry per concurrent connect in flight).
func (s *stateStore) pruneLocked() {
	now := time.Now()
	for k, v := range s.m {
		if now.After(v.Expires) {
			delete(s.m, k)
		}
	}
}

// HandlerDeps groups everything the connect/callback handlers need.
type HandlerDeps struct {
	Tickets         *TicketSigner
	Tokens          secrets.TokenStore
	Registry        *Registry
	CallbackBaseURL string // optional override for redirect_uri base

	// TrustForwardedHeaders, if true, lets the auto-derived callback base URL
	// honour X-Forwarded-Proto / X-Forwarded-Host. Default false: those
	// headers are caller-controlled and should only be trusted when the admin
	// port sits behind a proxy that strips/overwrites them. Has no effect
	// when CallbackBaseURL is set.
	TrustForwardedHeaders bool

	// OnSuccess is invoked after a successful callback. Tokens are already
	// persisted by the time it runs; the gateway uses it to register the
	// upstream's tools on the federated server. Returning an error renders a
	// "connected, but tool list pending" page so the user knows to retry —
	// tokens are kept either way.
	OnSuccess func(ctx context.Context, backend, userID string) error
}

// Handler exposes the HTTP handlers for OAuth connect/callback.
type Handler struct {
	deps  HandlerDeps
	state *stateStore
}

// New returns a Handler bound to the given dependencies.
func New(deps HandlerDeps) *Handler {
	return &Handler{deps: deps, state: newStateStore()}
}

// HandleConnect verifies the connect ticket, builds an authorization URL for
// the requested backend, and redirects the user there. The state and PKCE
// verifier are stashed for HandleCallback.
//
// URL shape: /oauth/connect/{backend}?ticket=<signed>
func (h *Handler) HandleConnect(w http.ResponseWriter, r *http.Request) {
	backend := pathSuffix(r.URL.Path, ConnectPath)
	if backend == "" {
		http.Error(w, "missing backend in path", http.StatusBadRequest)
		return
	}
	ticket := r.URL.Query().Get("ticket")
	if ticket == "" {
		http.Error(w, "missing ticket", http.StatusUnauthorized)
		return
	}
	uid, tBackend, err := h.deps.Tickets.Verify(ticket)
	if err != nil {
		http.Error(w, "invalid ticket: "+err.Error(), http.StatusUnauthorized)
		return
	}
	if tBackend != backend {
		http.Error(w, "ticket/backend mismatch", http.StatusBadRequest)
		return
	}
	cfg, ok := h.deps.Registry.Get(backend)
	if !ok {
		http.Error(w, "unknown backend", http.StatusNotFound)
		return
	}
	if err := cfg.Endpoints.Validate(); err != nil {
		http.Error(w, "backend oauth misconfigured: "+err.Error(), http.StatusInternalServerError)
		return
	}

	redirect := h.callbackURL(r, backend)

	// Dynamic Client Registration: if the operator did not pre-register an
	// OAuth app, register one on the fly against the upstream's
	// registration_endpoint. The resulting client_id (and optional secret) is
	// stashed on the registry so future users of the same backend reuse it.
	//
	// Concurrent connects for the same backend coalesce on a per-backend
	// lock so we don't double-register against the upstream and don't mutate
	// the shared *BackendConfig from two goroutines at once.
	if cfg.ClientID == "" {
		if cfg.Endpoints.RegistrationURL == "" {
			http.Error(w, "backend "+backend+" requires a clientId but upstream did not advertise a registration_endpoint — set auth.clientId in config", http.StatusInternalServerError)
			return
		}
		updated, err := h.ensureRegisteredClient(r.Context(), backend, redirect)
		if err != nil {
			http.Error(w, "dynamic client registration failed: "+err.Error(), http.StatusBadGateway)
			return
		}
		cfg = updated
	}

	pkce, err := NewPKCE()
	if err != nil {
		http.Error(w, "pkce: "+err.Error(), http.StatusInternalServerError)
		return
	}
	state, err := RandomState()
	if err != nil {
		http.Error(w, "state: "+err.Error(), http.StatusInternalServerError)
		return
	}
	h.state.put(state, &stateEntry{
		UserID:       uid,
		Backend:      backend,
		PKCEVerifier: pkce.Verifier,
		RedirectURI:  redirect,
		Expires:      time.Now().Add(10 * time.Minute),
	})
	authURL := AuthCodeURL(cfg.Endpoints, cfg.ClientID, redirect, state, pkce, cfg.Scopes)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// HandleCallback receives the user back from the upstream authorization
// server, exchanges the code, and persists the tokens.
//
// URL shape: /oauth/callback/{backend}?state=...&code=...
func (h *Handler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	backend := pathSuffix(r.URL.Path, CallbackPath)
	if backend == "" {
		writeCallbackError(w, "missing backend in path")
		return
	}
	if upstreamErr := r.URL.Query().Get("error"); upstreamErr != "" {
		desc := r.URL.Query().Get("error_description")
		writeCallbackError(w, fmt.Sprintf("%s: %s", upstreamErr, desc))
		return
	}
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if state == "" || code == "" {
		writeCallbackError(w, "missing state or code")
		return
	}
	entry := h.state.take(state)
	if entry == nil {
		writeCallbackError(w, "state expired or unknown — start the flow again")
		return
	}
	if entry.Backend != backend {
		writeCallbackError(w, "state/backend mismatch")
		return
	}
	cfg, ok := h.deps.Registry.Get(backend)
	if !ok {
		writeCallbackError(w, "unknown backend")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	tokens, err := ExchangeCode(ctx, cfg.Endpoints, cfg.ClientID, cfg.ClientSecret, code, entry.PKCEVerifier, entry.RedirectURI)
	if err != nil {
		slog.Error("oauth: code exchange failed", "backend", backend, "user", entry.UserID, "error", err)
		writeCallbackError(w, "token exchange failed: "+err.Error())
		return
	}
	if err := h.deps.Tokens.Save(entry.UserID, backend, tokens); err != nil {
		writeCallbackError(w, "persist tokens: "+err.Error())
		return
	}
	if h.deps.OnSuccess != nil {
		if err := h.deps.OnSuccess(r.Context(), backend, entry.UserID); err != nil {
			slog.Warn("oauth: post-callback hook failed", "backend", backend, "user", entry.UserID, "error", err.Error())
			writeCallbackPartial(w, backend, entry.UserID, err.Error())
			return
		}
	}
	writeCallbackSuccess(w, backend, entry.UserID)
}

// ensureRegisteredClient runs Dynamic Client Registration under a per-backend
// lock so concurrent connects for the same backend don't double-register on
// the upstream. The resulting credentials are written into a fresh
// BackendConfig (copy-on-write) and swapped into the registry; the original
// pointer is left untouched so the Refresher cannot observe a half-mutated
// struct.
func (h *Handler) ensureRegisteredClient(ctx context.Context, backend, redirect string) (*BackendConfig, error) {
	unlock := h.deps.Registry.LockForUpdate(backend)
	defer unlock()

	// Re-read inside the lock — a sibling request may have just finished DCR.
	cfg, ok := h.deps.Registry.Get(backend)
	if !ok {
		return nil, fmt.Errorf("backend %q vanished from registry mid-flow", backend)
	}
	if cfg.ClientID != "" {
		return cfg, nil
	}
	reg, err := RegisterClient(ctx, cfg.Endpoints.RegistrationURL, "agentsmith", redirect, cfg.Scopes)
	if err != nil {
		return nil, err
	}
	updated := *cfg
	updated.ClientID = reg.ClientID
	updated.ClientSecret = reg.ClientSecret
	h.deps.Registry.Set(&updated)
	return &updated, nil
}

// callbackURL builds the absolute redirect_uri sent to the authorization
// server. The explicit override wins; otherwise we derive scheme+host from
// the incoming request. X-Forwarded-* headers are only honoured when the
// operator opted in via TrustForwardedHeaders, since those headers are
// caller-controlled and could otherwise let an attacker reaching the admin
// port redirect callbacks to an arbitrary host.
func (h *Handler) callbackURL(r *http.Request, backend string) string {
	base := h.deps.CallbackBaseURL
	if base == "" {
		base = deriveBaseURL(r, h.deps.TrustForwardedHeaders)
	}
	return strings.TrimRight(base, "/") + CallbackPath + backend
}

// deriveBaseURL returns scheme://host derived from a request. When
// trustForwarded is true, X-Forwarded-Proto and X-Forwarded-Host take
// precedence — only safe when the listening port sits behind a proxy that
// strips/overwrites those headers.
func deriveBaseURL(r *http.Request, trustForwarded bool) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if trustForwarded {
		if v := r.Header.Get("X-Forwarded-Proto"); v != "" {
			scheme = strings.TrimSpace(strings.Split(v, ",")[0])
		}
		if v := r.Header.Get("X-Forwarded-Host"); v != "" {
			host = strings.TrimSpace(strings.Split(v, ",")[0])
		}
	}
	return scheme + "://" + host
}

// pathSuffix returns whatever follows prefix in p, or "" if p does not start
// with prefix. Used to extract the backend name from /oauth/connect/{name}.
func pathSuffix(p, prefix string) string {
	if !strings.HasPrefix(p, prefix) {
		return ""
	}
	return strings.TrimPrefix(p, prefix)
}

// BuildConnectURL returns the absolute URL a user clicks to start an OAuth
// flow. Tool handlers surface this in their error message when an upstream
// has no tokens for the calling user.
func BuildConnectURL(baseURL, backend, ticket string) string {
	return fmt.Sprintf("%s%s%s?ticket=%s", strings.TrimRight(baseURL, "/"), ConnectPath, backend, ticket)
}

// writeCallbackSuccess renders the minimal HTML success page shown after a
// successful OAuth round-trip. The user closes the tab and retries their
// tool call.
func writeCallbackSuccess(w http.ResponseWriter, backend, user string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	page := successPage(backend, user)
	_, _ = w.Write([]byte(page))
}

// writeCallbackError renders the corresponding failure page.
func writeCallbackError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	page := errorPage(msg)
	_, _ = w.Write([]byte(page))
}

// writeCallbackPartial renders the page shown when OAuth succeeded (tokens
// are persisted) but the post-callback hook failed — typically tool
// registration on the federated server. The user can retry by visiting the
// connect URL again; the gateway will skip the OAuth round-trip and rerun
// the hook.
func writeCallbackPartial(w http.ResponseWriter, backend, user, reason string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	page := partialPage(backend, user, reason)
	_, _ = w.Write([]byte(page))
}

// successPage and errorPage assemble the post-OAuth HTML pages, escaping
// every interpolated value via html.EscapeString. Pulled out so the writer
// helpers above feed only static + escaped content to ResponseWriter (gosec
// flags Fprintf-with-format-string-of-html even when the values are escaped).
func successPage(backend, user string) string {
	var b strings.Builder
	b.WriteString(`<!doctype html><html><head><meta charset="utf-8"><title>Connected</title>`)
	b.WriteString(`<style>body{font-family:system-ui,sans-serif;max-width:480px;margin:4rem auto;padding:0 1rem;color:#1f2937}.ok{color:#059669}</style>`)
	b.WriteString(`</head><body><h2 class="ok">✓ Connected</h2><p>Your <strong>`)
	b.WriteString(htmlEscape(backend))
	b.WriteString(`</strong> account is now connected (as <code>`)
	b.WriteString(htmlEscape(user))
	b.WriteString(`</code>). You can close this tab and retry your tool call.</p></body></html>`)
	return b.String()
}

func errorPage(msg string) string {
	var b strings.Builder
	b.WriteString(`<!doctype html><html><head><meta charset="utf-8"><title>OAuth error</title>`)
	b.WriteString(`<style>body{font-family:system-ui,sans-serif;max-width:560px;margin:4rem auto;padding:0 1rem;color:#1f2937}.err{color:#dc2626}</style>`)
	b.WriteString(`</head><body><h2 class="err">✗ OAuth flow failed</h2><p>`)
	b.WriteString(htmlEscape(msg))
	b.WriteString(`</p><p>Close this tab and start the flow again from your MCP client.</p></body></html>`)
	return b.String()
}

// partialPage is rendered when tokens were saved but the post-callback hook
// (tool registration) failed. It explicitly tells the user that retrying the
// connect link will rerun the hook without going through OAuth again.
func partialPage(backend, user, reason string) string {
	var b strings.Builder
	b.WriteString(`<!doctype html><html><head><meta charset="utf-8"><title>Partial connect</title>`)
	b.WriteString(`<style>body{font-family:system-ui,sans-serif;max-width:560px;margin:4rem auto;padding:0 1rem;color:#1f2937}.warn{color:#d97706}</style>`)
	b.WriteString(`</head><body><h2 class="warn">Connected, but tools not yet available</h2><p>Your <strong>`)
	b.WriteString(htmlEscape(backend))
	b.WriteString(`</strong> account is linked (as <code>`)
	b.WriteString(htmlEscape(user))
	b.WriteString(`</code>) and the gateway has stored your tokens — that part succeeded. However, registering the backend's tool catalog on the federated server failed:</p><pre>`)
	b.WriteString(htmlEscape(reason))
	b.WriteString(`</pre><p>Re-open the connect link from your MCP client to retry; the gateway will reuse your stored tokens and skip the OAuth round-trip.</p></body></html>`)
	return b.String()
}

// htmlEscape is a tiny replacement for html.EscapeString to avoid the
// dependency for a single-call use. Handles only the characters that matter
// for safe injection into <p> text nodes and <code> blocks.
func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")
	return r.Replace(s)
}

