// Package admin exposes a small HTTP server for operational visibility into
// agentsmith's runtime state. It is intentionally separate from the MCP server
// so the two concerns live on different ports and can be firewalled independently.
//
// Current endpoints:
//
//	GET /healthz   — liveness check; 200 when ≥1 backend is connected, 503 otherwise
//	GET /backends  — full per-backend status as a JSON array
package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/sebastienmelki/agentsmith/internal/gateway"
)

// gatewaySource is the subset of Gateway the admin server needs. Keeping it
// as an interface makes the handler easy to test without a real gateway.
type gatewaySource interface {
	Backends() []gateway.BackendStatus
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

// writeJSON encodes v as JSON and writes it to w with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("admin: failed to encode response", "error", err)
	}
}
