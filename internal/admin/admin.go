// Package admin exposes a small HTTP server for operational visibility into
// agentsmith's runtime state. It is intentionally separate from the MCP server
// so the two concerns live on different ports and can be firewalled independently.
//
// Endpoints:
//
//	GET /                          — live dashboard (HTML)
//	GET /healthz                   — liveness check (JSON)
//	GET /backends                  — per-backend status array (JSON)
//	GET /ui/backends               — BackendsPanel htmx partial
//	GET /ui/backends/{name}        — backend detail page (HTML)
//	GET /ui/backends/{name}/status — detail-page status-strip partial (htmx poll)
package admin

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/sebastienmelki/agentsmith/internal/admin/ui"
	"github.com/sebastienmelki/agentsmith/internal/gateway"
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
	gw gatewaySource
}

// New returns an admin Server backed by the given Gateway.
func New(gw *gateway.Gateway) *Server {
	return &Server{gw: gw}
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
	mux.HandleFunc("GET /{$}", s.handleDashboard)
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
	if err := ui.Dashboard(backends, metrics).Render(r.Context(), w); err != nil {
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
	if err := ui.BackendDetailPage(detail).Render(r.Context(), w); err != nil {
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

// writeJSON encodes v as JSON and writes it to w with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("admin: failed to encode response", "error", err)
	}
}
