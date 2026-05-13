// Package admin exposes a small HTTP server for operational visibility into
// agentsmith's runtime state. It is intentionally separate from the MCP server
// so the two concerns live on different ports and can be firewalled independently.
//
// Endpoints:
//
//	GET    /                          — live dashboard (HTML)
//	GET    /healthz                   — liveness check (JSON)
//	GET    /backends                  — per-backend status array (JSON)
//	GET    /ui/backends               — BackendsPanel htmx partial
//	GET    /ui/backends/{name}        — backend detail page (HTML)
//	GET    /ui/backends/{name}/status — detail-page status-strip partial (htmx poll)
//	GET    /users                     — users page (HTML) + JSON if Accept: application/json
//	POST   /users                     — create user, returns api_key once
//	DELETE /users/{id}                — revoke user
//	GET    /oauth/connect/{backend}   — start upstream OAuth flow
//	GET    /oauth/callback/{backend}  — upstream OAuth callback
package admin

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/sebastienmelki/agentsmith/internal/admin/ui"
	"github.com/sebastienmelki/agentsmith/internal/config"
	"github.com/sebastienmelki/agentsmith/internal/gateway"
	"github.com/sebastienmelki/agentsmith/internal/identity"
	"github.com/sebastienmelki/agentsmith/internal/oauth"
)

// gatewaySource is the subset of Gateway the admin server needs. Keeping it
// as an interface makes the handler easy to test without a real gateway.
type gatewaySource interface {
	Backends() []gateway.BackendStatus
	BackendDetails() []gateway.BackendDetail
	BackendByName(name string) (gateway.BackendDetail, bool)
	AggregateMetrics() gateway.Metrics
	SubscribeLogs(name string) (ch chan gateway.CallEntry, unsub func(), ok bool)
}

// Server is the admin HTTP server.
type Server struct {
	gw       gatewaySource
	users    identity.Store
	oauthH   *oauth.Handler // nil when no OAuth backends are configured
	authMode config.AuthMode
}

// Options groups the admin server's dependencies. Pass nil for OAuthHandler
// when no upstream uses OAuth.
type Options struct {
	Users        identity.Store
	OAuthHandler *oauth.Handler
	AuthMode     config.AuthMode
}

// New returns an admin Server backed by the given Gateway and options.
func New(gw *gateway.Gateway, opts Options) *Server {
	return &Server{
		gw:       gw,
		users:    opts.Users,
		oauthH:   opts.OAuthHandler,
		authMode: opts.AuthMode,
	}
}

// Handler returns an http.Handler wiring up all admin routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /backends", s.handleBackends)
	mux.HandleFunc("GET /ui/backends", s.handleBackendsUI)
	mux.HandleFunc("GET /ui/backends/{name}/logs/stream", s.handleLogStream)
	mux.HandleFunc("GET /ui/backends/{name}/status", s.handleBackendDetailStatus)
	mux.HandleFunc("GET /ui/backends/{name}", s.handleBackendDetail)
	mux.HandleFunc("GET /users", s.handleUsers)
	mux.HandleFunc("POST /users", s.handleCreateUser)
	mux.HandleFunc("DELETE /users/{id}", s.handleDeleteUser)
	mux.HandleFunc("GET /{$}", s.handleDashboard)

	// OAuth routes are only mounted when at least one backend uses OAuth.
	if s.oauthH != nil {
		mux.HandleFunc("GET "+oauth.ConnectPath+"{backend}", s.oauthH.HandleConnect)
		mux.HandleFunc("GET "+oauth.CallbackPath+"{backend}", s.oauthH.HandleCallback)
	}
	return mux
}

// handleHealthz returns 200 when at least one backend is connected, 503
// otherwise. Suitable as both a liveness and a readiness probe.
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	backends := s.gw.Backends()

	connected := 0
	for _, b := range backends {
		if b.State == gateway.StateConnected {
			connected++
		}
	}

	type response struct {
		Status            string `json:"status"`
		ConnectedBackends int    `json:"connectedBackends"`
		TotalBackends     int    `json:"totalBackends"`
	}

	resp := response{
		ConnectedBackends: connected,
		TotalBackends:     len(backends),
	}

	if connected > 0 {
		resp.Status = "ok"
		writeJSON(w, http.StatusOK, resp)
	} else {
		resp.Status = "degraded"
		writeJSON(w, http.StatusServiceUnavailable, resp)
	}
}

// handleBackends returns the full status of every configured backend as a JSON
// array, regardless of their current state.
func (s *Server) handleBackends(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.gw.Backends())
}

// handleDashboard renders the full admin dashboard HTML page.
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	backends := s.gw.BackendDetails()
	metrics := s.gw.AggregateMetrics()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := ui.Dashboard(backends, metrics, s.unprotected()).Render(r.Context(), w); err != nil {
		slog.Error("admin: failed to render dashboard", "error", err)
	}
}

// handleBackendsUI returns the BackendsPanel component as an HTML partial.
// htmx polls this endpoint every 5 s and swaps in the updated panel.
func (s *Server) handleBackendsUI(w http.ResponseWriter, r *http.Request) {
	backends := s.gw.BackendDetails()
	metrics := s.gw.AggregateMetrics()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := ui.BackendsPanel(backends, metrics).Render(r.Context(), w); err != nil {
		slog.Error("admin: failed to render backends panel", "error", err)
	}
}

// handleBackendDetail renders the full detail page for a single backend.
func (s *Server) handleBackendDetail(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	detail, ok := s.gw.BackendByName(name)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := ui.BackendDetailPage(detail, s.unprotected()).Render(r.Context(), w); err != nil {
		slog.Error("admin: failed to render backend detail", "name", name, "error", err)
	}
}

// handleBackendDetailStatus returns the polled status-strip wrapper. The tool
// list isn't included here — keeping it out of the 5 s swap is what preserves
// users' expanded <details> state.
func (s *Server) handleBackendDetailStatus(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	detail, ok := s.gw.BackendByName(name)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := ui.StatusPolled(detail).Render(r.Context(), w); err != nil {
		slog.Error("admin: failed to render backend status partial", "name", name, "error", err)
	}
}

// handleLogStream streams new CallEntry values to the client as Server-Sent Events.
// Each event is a JSON-encoded CallEntry on the "log" event channel.
func (s *Server) handleLogStream(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	ch, unsub, ok := s.gw.SubscribeLogs(name)
	if !ok {
		http.NotFound(w, r)
		return
	}
	defer unsub()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx buffering if present

	rc := http.NewResponseController(w)

	// Send a comment heartbeat every 15 s to keep the connection alive through
	// proxies and load balancers that close idle connections.
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			fmt.Fprintf(w, ": heartbeat\n\n")
			_ = rc.Flush()
		case entry := <-ch:
			data, err := json.Marshal(entry)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: log\ndata: %s\n\n", data)
			_ = rc.Flush()
		}
	}
}

// handleUsers renders the users page (HTML) or returns the user list as JSON
// when the client asks for it via Accept.
func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	if s.users == nil {
		http.Error(w, "users not configured", http.StatusInternalServerError)
		return
	}
	users := s.users.List()
	if wantsJSON(r) {
		writeJSON(w, http.StatusOK, users)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := ui.UsersPage(users, s.authMode == config.ModeProtected, s.unprotected()).Render(r.Context(), w); err != nil {
		slog.Error("admin: failed to render users page", "error", err)
	}
}

// handleCreateUser creates a user and returns the freshly-minted API key. The
// plaintext key is only shown here; subsequent reads only see metadata.
func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	if s.users == nil {
		http.Error(w, "users not configured", http.StatusInternalServerError)
		return
	}
	if s.authMode != config.ModeProtected {
		http.Error(w, "user creation only valid in protected mode", http.StatusForbidden)
		return
	}
	var body struct {
		Email string `json:"email"`
	}
	// Accept both JSON and form bodies for convenience.
	switch ct := r.Header.Get("Content-Type"); {
	case strings.HasPrefix(ct, "application/json"):
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
			return
		}
	default:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form: "+err.Error(), http.StatusBadRequest)
			return
		}
		body.Email = r.PostForm.Get("email")
	}
	if body.Email == "" {
		http.Error(w, "email is required", http.StatusBadRequest)
		return
	}
	user, key, err := s.users.Create(body.Email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if wantsJSON(r) {
		writeJSON(w, http.StatusCreated, map[string]any{
			"user":    user,
			"api_key": key,
		})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := ui.UserCreatedPage(user, key, s.unprotected()).Render(r.Context(), w); err != nil {
		slog.Error("admin: failed to render user-created page", "error", err)
	}
}

// handleDeleteUser revokes a user. Idempotent — deleting a non-existent user
// is not an error.
func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if s.users == nil {
		http.Error(w, "users not configured", http.StatusInternalServerError)
		return
	}
	id := r.PathValue("id")
	if err := s.users.Delete(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// unprotected reports whether the gateway is currently in ModeUnprotected.
// Templates read this to decide whether to show the warning banner.
func (s *Server) unprotected() bool {
	return s.authMode != config.ModeProtected
}

// wantsJSON returns true when the client signalled it wants JSON via the
// Accept header. The HTML pages render by default so a curl/wget user sees
// readable text; an MCP client or our own UI can opt into JSON.
func wantsJSON(r *http.Request) bool {
	a := r.Header.Get("Accept")
	return strings.Contains(a, "application/json")
}

// writeJSON encodes v as JSON and writes it to w with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("admin: failed to encode response", "error", err)
	}
}
