// Package gateway connects to one or more MCP backends and federates their
// tools behind a single namespaced MCP server.
package gateway

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sebastienmelki/agentsmith/internal/config"
)

const (
	namespaceSep   = "__"
	connectTimeout = 15 * time.Second
	listTimeout    = 15 * time.Second
	initialBackoff = 2 * time.Second
	maxBackoff     = 2 * time.Minute
)

// BackendState describes the current connectivity state of a backend.
type BackendState string

// Possible values of BackendState.
const (
	StateConnecting BackendState = "connecting"
	StateConnected  BackendState = "connected"
	StateError      BackendState = "error"
)

// BackendStatus is a point-in-time snapshot of a backend, safe to JSON-encode
// and expose through the admin API.
type BackendStatus struct {
	Name              string       `json:"name"`
	URL               string       `json:"url"`
	State             BackendState `json:"state"`
	LastError         string       `json:"lastError,omitempty"`
	LastConnectedAt   *time.Time   `json:"lastConnectedAt,omitempty"`
	ReconnectAttempts int          `json:"reconnectAttempts"`
	ToolCount         int          `json:"toolCount"`
}

// backend holds all mutable state for one upstream MCP target.
type backend struct {
	// immutable after creation
	name    string
	url     string
	headers map[string]string
	// client is reused across reconnects; a fresh transport is created per dial.
	client *mcp.Client

	mu                sync.RWMutex
	state             BackendState
	session           *mcp.ClientSession
	lastErr           error
	lastConnectedAt   *time.Time
	reconnectAttempts int
	toolCount         int
	toolsRegistered   bool // true after the first successful ListTools+AddTool
}

// getSession returns the live session (and true) under an RLock. Tool dispatch
// calls this so reconnects are transparent to the MCP server layer.
func (b *backend) getSession() (*mcp.ClientSession, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.state != StateConnected || b.session == nil {
		return nil, false
	}
	return b.session, true
}

// snapshot returns a safe copy of the backend's current status.
func (b *backend) snapshot() BackendStatus {
	b.mu.RLock()
	defer b.mu.RUnlock()
	s := BackendStatus{
		Name:              b.name,
		URL:               b.url,
		State:             b.state,
		ReconnectAttempts: b.reconnectAttempts,
		ToolCount:         b.toolCount,
	}
	if b.lastErr != nil {
		s.LastError = b.lastErr.Error()
	}
	if b.lastConnectedAt != nil {
		t := *b.lastConnectedAt
		s.LastConnectedAt = &t
	}
	return s
}

// Gateway federates one or more MCP backends behind a single Streamable HTTP
// endpoint, namespacing each backend's tools with "<target>__<tool>". Each
// backend runs its own reconnect loop so the gateway stays available even when
// individual upstreams are temporarily down.
type Gateway struct {
	server   *mcp.Server
	backends []*backend
}

// New creates the federated MCP server and fires a background connectLoop for
// each configured target. It returns immediately — no backend needs to be
// reachable at startup.
func New(ctx context.Context, cfg *config.Config) (*Gateway, error) {
	g := &Gateway{
		server: mcp.NewServer(&mcp.Implementation{Name: "agentsmith", Version: "v0.0.1"}, nil),
	}
	for _, t := range cfg.Targets {
		// KeepAlive proactively detects silent TCP failures instead of waiting
		// for the next tool call to hit the 60 s HTTP timeout.
		client := mcp.NewClient(
			&mcp.Implementation{Name: "agentsmith", Version: "v0.0.1"},
			&mcp.ClientOptions{KeepAlive: 5 * time.Second},
		)
		b := &backend{
			name:    t.Name,
			url:     t.URL,
			headers: t.Headers,
			client:  client,
			state:   StateConnecting,
		}
		g.backends = append(g.backends, b)
		go g.connectLoop(ctx, b)
	}
	return g, nil
}

// Server returns the federated MCP server. It is ready to handle HTTP traffic
// immediately; backends that are still connecting will return a clear
// "unavailable" error from their tool handlers until they come up.
func (g *Gateway) Server() *mcp.Server {
	return g.server
}

// Backends returns a point-in-time status snapshot for every configured backend.
func (g *Gateway) Backends() []BackendStatus {
	out := make([]BackendStatus, len(g.backends))
	for i, b := range g.backends {
		out[i] = b.snapshot()
	}
	return out
}

// Close terminates all live backend sessions. Errors are swallowed because
// this is only called during shutdown.
func (g *Gateway) Close() {
	for _, b := range g.backends {
		b.mu.RLock()
		sess := b.session
		b.mu.RUnlock()
		if sess != nil {
			_ = sess.Close()
		}
	}
}

// connectLoop runs in a dedicated goroutine for each backend. It dials,
// registers tools on the first successful connection, then blocks on
// sess.Wait(). When the session ends it reconnects with exponential backoff.
//
// Backoff: 2 s → 4 s → … → 2 min cap, with ±10 % jitter to avoid
// thundering-herd reconnects when multiple backends restart simultaneously.
func (g *Gateway) connectLoop(ctx context.Context, b *backend) {
	backoff := initialBackoff

	for {
		if ctx.Err() != nil {
			return
		}

		b.mu.Lock()
		b.state = StateConnecting
		b.reconnectAttempts++
		attempt := b.reconnectAttempts
		b.mu.Unlock()

		slog.Info("dialing backend", "name", b.name, "attempt", attempt)

		sess, err := g.dial(ctx, b)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			b.mu.Lock()
			b.state = StateError
			b.lastErr = err
			b.mu.Unlock()

			wait := backoff + rand.N(backoff/10) //nolint:gosec // backoff jitter does not require cryptographic randomness
			slog.Warn("backend dial failed", "name", b.name, "error", err, "retry_in", wait)
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
			backoff = min(backoff*2, maxBackoff)
			continue
		}

		// Successful dial — update state and reset the backoff counter.
		now := time.Now()
		b.mu.Lock()
		b.state = StateConnected
		b.session = sess
		b.lastErr = nil
		b.lastConnectedAt = &now
		b.mu.Unlock()
		backoff = initialBackoff

		slog.Info("backend connected", "name", b.name)

		// Register tools exactly once. Handlers close over *backend so they
		// automatically pick up the new session on every subsequent reconnect.
		b.mu.RLock()
		registered := b.toolsRegistered
		b.mu.RUnlock()
		if !registered {
			if err := g.registerTools(ctx, b, sess); err != nil {
				slog.Warn("failed to register tools", "name", b.name, "error", err)
				b.mu.Lock()
				b.lastErr = err
				b.mu.Unlock()
			}
		}

		// Block until the session is closed by the server, a keepalive timeout,
		// or a fatal transport error.
		if err := sess.Wait(); err != nil && !errors.Is(err, context.Canceled) {
			slog.Warn("backend session closed with error", "name", b.name, "error", err)
		} else {
			slog.Info("backend session closed", "name", b.name)
		}

		b.mu.Lock()
		b.state = StateError
		b.session = nil
		b.lastErr = errors.New("session closed")
		b.mu.Unlock()

		// Small jitter before the next dial attempt.
		select {
		case <-ctx.Done():
			return
		case <-time.After(rand.N(initialBackoff / 5)): //nolint:gosec // reconnect jitter does not require cryptographic randomness
		}
	}
}

// dial builds a fresh single-use transport and performs the MCP handshake.
func (g *Gateway) dial(ctx context.Context, b *backend) (*mcp.ClientSession, error) {
	httpClient := &http.Client{
		Timeout:   60 * time.Second,
		Transport: &headerInjector{base: http.DefaultTransport, headers: b.headers},
	}
	// StreamableClientTransport is single-use per the SDK contract.
	transport := &mcp.StreamableClientTransport{
		Endpoint:   b.url,
		HTTPClient: httpClient,
	}
	connectCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	return b.client.Connect(connectCtx, transport, nil)
}

// registerTools lists the backend's tools and registers each one on the
// federated server under the namespaced name "<backend>__<tool>". Called at
// most once per backend lifetime.
func (g *Gateway) registerTools(ctx context.Context, b *backend, sess *mcp.ClientSession) error {
	listCtx, cancel := context.WithTimeout(ctx, listTimeout)
	result, err := sess.ListTools(listCtx, nil)
	cancel()
	if err != nil {
		return fmt.Errorf("list tools from %q: %w", b.name, err)
	}

	for _, t := range result.Tools {
		namespaced := *t
		namespaced.Name = b.name + namespaceSep + t.Name
		originalName := t.Name
		g.server.AddTool(&namespaced, g.makeHandler(b, originalName))
	}

	b.mu.Lock()
	b.toolsRegistered = true
	b.toolCount = len(result.Tools)
	b.mu.Unlock()

	slog.Info("registered tools", "backend", b.name, "count", len(result.Tools))
	return nil
}

// makeHandler returns a ToolHandler that resolves the live session at call
// time, making reconnects invisible to the MCP server layer.
func (g *Gateway) makeHandler(b *backend, originalName string) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		sess, ok := b.getSession()
		if !ok {
			return nil, fmt.Errorf("backend %q is currently unavailable", b.name)
		}
		slog.Info("tool call", "backend", b.name, "tool", originalName)
		var args any
		if len(req.Params.Arguments) > 0 {
			args = req.Params.Arguments
		}
		return sess.CallTool(ctx, &mcp.CallToolParams{
			Name:      originalName,
			Arguments: args,
			Meta:      req.Params.Meta,
		})
	}
}

// SplitNamespacedTool reverses the namespacing applied at registration. Useful
// for downstream consumers that want to display the source backend separately
// from the tool name.
func SplitNamespacedTool(name string) (target, tool string, ok bool) {
	before, after, ok := strings.Cut(name, namespaceSep)
	if !ok {
		return "", name, false
	}
	return before, after, true
}

// headerInjector is a per-target RoundTripper that adds only that target's
// headers to outgoing requests, keeping secrets scoped per backend.
type headerInjector struct {
	base    http.RoundTripper
	headers map[string]string
}

func (h *headerInjector) RoundTrip(req *http.Request) (*http.Response, error) {
	for k, v := range h.headers {
		req.Header.Set(k, v)
	}
	return h.base.RoundTrip(req)
}
