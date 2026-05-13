// Package gateway connects to one or more MCP backends and federates their
// tools behind a single namespaced MCP server.
package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math/rand/v2"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sebastienmelki/agentsmith/internal/config"
	"github.com/sebastienmelki/agentsmith/internal/identity"
	"github.com/sebastienmelki/agentsmith/internal/oauth"
	"github.com/sebastienmelki/agentsmith/internal/secrets"
)

const (
	namespaceSep   = "__"
	connectTimeout = 15 * time.Second
	listTimeout    = 15 * time.Second
	initialBackoff = 2 * time.Second
	maxBackoff     = 2 * time.Minute
	connectTicketTTL = 10 * time.Minute
)

// BackendState describes the current connectivity state of a backend.
type BackendState string

// Possible values of BackendState.
const (
	StateConnecting    BackendState = "connecting"
	StateConnected     BackendState = "connected"
	StateError         BackendState = "error"
	StateAwaitingAuth  BackendState = "awaiting_auth"
)

// BackendStatus is a point-in-time snapshot of a backend, safe to JSON-encode
// and expose through the admin API.
type BackendStatus struct {
	Name              string       `json:"name"`
	URL               string       `json:"url"`
	State             BackendState `json:"state"`
	AuthType          string       `json:"authType"` // "static" or "oauth"
	LastError         string       `json:"lastError,omitempty"`
	LastConnectedAt   *time.Time   `json:"lastConnectedAt,omitempty"`
	ReconnectAttempts int          `json:"reconnectAttempts"`
	ToolCount         int          `json:"toolCount"`
}

// ParamInfo describes a single input parameter extracted from a tool's JSON Schema.
type ParamInfo struct {
	Name        string `json:"name"`
	Type        string `json:"type,omitempty"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required"`
	Default     string `json:"default,omitempty"` // JSON-encoded default value
}

// ToolInfo is a fully hydrated representation of a backend tool for display.
type ToolInfo struct {
	Name         string      `json:"name"`
	Title        string      `json:"title,omitempty"`
	Description  string      `json:"description,omitempty"`
	Params       []ParamInfo `json:"params"`
	InputSchema  string      `json:"inputSchema"`            // pretty-printed JSON
	OutputSchema string      `json:"outputSchema,omitempty"` // pretty-printed JSON
	// Annotation hints from the MCP spec.
	ReadOnly    bool  `json:"readOnly"`
	Idempotent  bool  `json:"idempotent"`
	Destructive *bool `json:"destructive,omitempty"`
	OpenWorld   *bool `json:"openWorld,omitempty"`
}

// CallEntry records a single tool invocation for the call log.
type CallEntry struct {
	ToolName   string    `json:"toolName"`
	UserID     string    `json:"userId,omitempty"`
	CalledAt   time.Time `json:"calledAt"`
	DurationMs int64     `json:"durationMs"`
	Success    bool      `json:"success"`
	Request    string    `json:"request,omitempty"`  // JSON-encoded arguments
	Response   string    `json:"response,omitempty"` // JSON-encoded result
	Error      string    `json:"error,omitempty"`
}

// Metrics holds lightweight aggregate counters for one backend.
// All fields are protected by the parent backend's mu.
type Metrics struct {
	TotalCalls  int64            `json:"totalCalls"`
	TotalErrors int64            `json:"totalErrors"`
	TotalMs     int64            `json:"totalMs"` // sum of all durations for avg
	PerTool     map[string]int64 `json:"perTool"` // call count keyed by tool name
}

// BackendDetail extends BackendStatus with the full hydrated tool list,
// metrics and the recent call log.
type BackendDetail struct {
	BackendStatus
	Tools   []ToolInfo  `json:"tools"`
	Metrics Metrics     `json:"metrics"`
	Log     []CallEntry `json:"log"` // most-recent-first, up to logCap entries
}

const logCap = 500 // ring-buffer capacity for call log

// userSession is a per-(user, backend) MCP client session for OAuth backends.
// Each one carries an Authorization: Bearer <access_token> header injected at
// dial time, so the upstream sees each user as a distinct caller.
type userSession struct {
	mu       sync.Mutex
	sess     *mcp.ClientSession
	lastUsed time.Time
}

// backend holds all mutable state for one upstream MCP target. Two shapes
// share this struct: static backends use the single sharedSession field and
// run a reconnect loop, while oauth backends lazily dial one userSession per
// caller and skip the reconnect loop entirely.
type backend struct {
	// immutable after creation
	name     string
	url      string
	headers  map[string]string // static-auth headers, empty for oauth backends
	authType string            // config.AuthTypeStatic or config.AuthTypeOAuth
	oauthCfg *oauth.BackendConfig

	// client is reused across reconnects for static backends. For oauth
	// backends each user dial constructs its own client.
	client *mcp.Client

	mu                sync.RWMutex
	state             BackendState
	sharedSession     *mcp.ClientSession // static backends only
	lastErr           error
	lastConnectedAt   *time.Time
	reconnectAttempts int
	toolCount         int
	toolsRegistered   bool        // true after the first successful ListTools+AddTool
	tools             []*mcp.Tool // stored on first successful registration

	// Per-user sessions for oauth backends. Keyed by user ID. Lazy-created on
	// the first tool call from that user; persists across calls until the
	// session dies, at which point we re-dial on the next call.
	userSessionsMu sync.Mutex
	userSessions   map[string]*userSession

	// metrics and call log — guarded by mu
	metrics  Metrics
	logBuf   [logCap]CallEntry // ring buffer
	logHead  int               // index of next write slot
	logCount int               // total entries written (capped at logCap)

	// logSubs receives a copy of every new CallEntry for SSE subscribers.
	// Channels are added/removed under mu.
	logSubs []chan CallEntry
}

// snapshot returns a safe copy of the backend's current status.
func (b *backend) snapshot() BackendStatus {
	b.mu.RLock()
	defer b.mu.RUnlock()
	s := BackendStatus{
		Name:              b.name,
		URL:               b.url,
		State:             b.state,
		AuthType:          b.authType,
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

// Deps is the gateway's external collaborators: token store for OAuth
// backends, signer for connect tickets, registry of OAuth client config, and
// the public URL used to build connect-link error messages. OAuth fields may
// be nil/empty when no backend uses OAuth.
type Deps struct {
	Tokens          *secrets.RefreshingTokenStore
	Tickets         *oauth.TicketSigner
	OAuthRegistry   *oauth.Registry
	CallbackBaseURL string // used in tool-error connect URLs
}

// Gateway federates one or more MCP backends behind a single Streamable HTTP
// endpoint, namespacing each backend's tools with "<target>__<tool>". Each
// backend runs its own reconnect loop so the gateway stays available even when
// individual upstreams are temporarily down.
type Gateway struct {
	server   *mcp.Server
	backends []*backend
	deps     Deps
}

// New creates the federated MCP server and fires a background connectLoop for
// each configured target. It returns immediately — no backend needs to be
// reachable at startup. For OAuth backends, the connect loop is skipped: tool
// registration happens lazily after the first user OAuths successfully.
func New(ctx context.Context, cfg *config.Config, deps Deps) (*Gateway, error) {
	g := &Gateway{
		server: mcp.NewServer(&mcp.Implementation{Name: "agentsmith", Version: "v0.0.1"}, nil),
		deps:   deps,
	}
	for _, t := range cfg.Targets {
		b := newBackend(t)
		g.backends = append(g.backends, b)
		if b.authType == config.AuthTypeOAuth {
			// OAuth backends start in awaiting_auth until the first user OAuths.
			b.mu.Lock()
			b.state = StateAwaitingAuth
			b.mu.Unlock()
		} else {
			go g.connectLoop(ctx, b)
		}
	}
	return g, nil
}

// newBackend builds a backend from a config target. The shared mcp.Client is
// only used by static backends — oauth backends get a fresh client per user
// dial because each carries different auth headers.
func newBackend(t config.Target) *backend {
	authType := config.AuthTypeStatic
	if t.Auth != nil && t.Auth.Type != "" {
		authType = t.Auth.Type
	}
	b := &backend{
		name:         t.Name,
		url:          t.URL,
		headers:      t.Headers,
		authType:     authType,
		state:        StateConnecting,
		userSessions: make(map[string]*userSession),
	}
	if authType == config.AuthTypeStatic {
		b.client = mcp.NewClient(
			&mcp.Implementation{Name: "agentsmith", Version: "v0.0.1"},
			&mcp.ClientOptions{KeepAlive: 5 * time.Second},
		)
	}
	return b
}

// SetOAuthConfig wires the resolved OAuth client config into the backend.
// Called from main once discovery (if any) has run.
func (g *Gateway) SetOAuthConfig(name string, cfg *oauth.BackendConfig) {
	for _, b := range g.backends {
		if b.name == name {
			b.mu.Lock()
			b.oauthCfg = cfg
			b.mu.Unlock()
			return
		}
	}
}

// RegisterToolsForOAuthBackend dials with the given user's tokens, lists the
// upstream's tools, and registers them on the federated server. Called once
// per OAuth backend, after the first user successfully completes OAuth.
// Idempotent — second calls are no-ops.
func (g *Gateway) RegisterToolsForOAuthBackend(ctx context.Context, backendName, userID string) error {
	b := g.backendByName(backendName)
	if b == nil {
		return fmt.Errorf("unknown backend %q", backendName)
	}
	b.mu.RLock()
	already := b.toolsRegistered
	b.mu.RUnlock()
	if already {
		return nil
	}
	sess, err := g.dialUserSession(ctx, b, userID)
	if err != nil {
		return err
	}
	if err := g.registerTools(ctx, b, sess); err != nil {
		return err
	}
	now := time.Now()
	b.mu.Lock()
	b.state = StateConnected
	b.lastConnectedAt = &now
	b.lastErr = nil
	b.mu.Unlock()
	return nil
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

// BackendDetails returns a lightweight detail snapshot (status + metrics, no
// tool list or call log) for every backend. Used by the dashboard panel where
// the full tool/log payload would be wasteful.
func (g *Gateway) BackendDetails() []BackendDetail {
	out := make([]BackendDetail, len(g.backends))
	for i, b := range g.backends {
		out[i] = BackendDetail{
			BackendStatus: b.snapshot(),
			Metrics:       b.metricsSnapshot(),
		}
	}
	return out
}

// Close terminates all live backend sessions. Errors are swallowed because
// this is only called during shutdown.
func (g *Gateway) Close() {
	for _, b := range g.backends {
		b.mu.RLock()
		sess := b.sharedSession
		b.mu.RUnlock()
		if sess != nil {
			_ = sess.Close()
		}
		b.userSessionsMu.Lock()
		for _, us := range b.userSessions {
			if us.sess != nil {
				_ = us.sess.Close()
			}
		}
		b.userSessionsMu.Unlock()
	}
}

// connectLoop runs in a dedicated goroutine for each static backend. It dials,
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

		sess, err := g.dialStatic(ctx, b)
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
		b.sharedSession = sess
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
		b.sharedSession = nil
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

// dialStatic builds a fresh single-use transport using the backend's static
// auth headers and performs the MCP handshake.
func (g *Gateway) dialStatic(ctx context.Context, b *backend) (*mcp.ClientSession, error) {
	httpClient := &http.Client{
		Timeout:   60 * time.Second,
		Transport: &headerInjector{base: http.DefaultTransport, headers: b.headers},
	}
	transport := &mcp.StreamableClientTransport{
		Endpoint:   b.url,
		HTTPClient: httpClient,
	}
	connectCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	return b.client.Connect(connectCtx, transport, nil)
}

// dialUserSession returns the live MCP client session for (b, userID),
// creating it lazily if missing. Pulls the user's OAuth access token from the
// token store at dial time and injects it as Authorization: Bearer.
//
// secrets.ErrNotFound is returned when the user has not yet completed OAuth
// for this backend — callers translate that into a connect-URL tool error.
func (g *Gateway) dialUserSession(ctx context.Context, b *backend, userID string) (*mcp.ClientSession, error) {
	b.userSessionsMu.Lock()
	us, ok := b.userSessions[userID]
	if !ok {
		us = &userSession{}
		b.userSessions[userID] = us
	}
	b.userSessionsMu.Unlock()

	us.mu.Lock()
	defer us.mu.Unlock()

	if us.sess != nil {
		us.lastUsed = time.Now()
		return us.sess, nil
	}

	tokens, err := g.deps.Tokens.Get(ctx, userID, b.name)
	if err != nil {
		return nil, err
	}
	scheme := tokens.TokenType
	if scheme == "" {
		scheme = "Bearer"
	}
	hdrs := map[string]string{"Authorization": scheme + " " + tokens.AccessToken}
	httpClient := &http.Client{
		Timeout:   60 * time.Second,
		Transport: &headerInjector{base: http.DefaultTransport, headers: hdrs},
	}
	transport := &mcp.StreamableClientTransport{
		Endpoint:   b.url,
		HTTPClient: httpClient,
	}
	client := mcp.NewClient(
		&mcp.Implementation{Name: "agentsmith", Version: "v0.0.1"},
		&mcp.ClientOptions{KeepAlive: 5 * time.Second},
	)
	connectCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	sess, err := client.Connect(connectCtx, transport, nil)
	if err != nil {
		return nil, fmt.Errorf("dial %s for user %s: %w", b.name, userID, err)
	}
	us.sess = sess
	us.lastUsed = time.Now()
	return sess, nil
}

// invalidateUserSession drops the cached session for (b, userID) so the next
// call will dial fresh. Used when an upstream returns 401 — likely the access
// token was revoked or rotated out of band.
func (b *backend) invalidateUserSession(userID string) {
	b.userSessionsMu.Lock()
	defer b.userSessionsMu.Unlock()
	us, ok := b.userSessions[userID]
	if !ok {
		return
	}
	if us.sess != nil {
		_ = us.sess.Close()
	}
	delete(b.userSessions, userID)
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

	toolsCopy := make([]*mcp.Tool, len(result.Tools))
	copy(toolsCopy, result.Tools)

	b.mu.Lock()
	b.toolsRegistered = true
	b.toolCount = len(result.Tools)
	b.tools = toolsCopy
	b.mu.Unlock()

	slog.Info("registered tools", "backend", b.name, "count", len(result.Tools))
	return nil
}

// makeHandler returns a ToolHandler that resolves the right session at call
// time — the shared one for static backends, the per-user one for oauth
// backends. Reconnects and token refreshes are transparent to the MCP server
// layer.
func (g *Gateway) makeHandler(b *backend, originalName string) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		userID := userIDFromContext(ctx)
		sess, errResult, err := g.resolveSession(ctx, b, userID)
		if err != nil {
			return nil, err
		}
		if errResult != nil {
			b.recordCall(originalName, userID, time.Now(), nil, errResult, nil)
			return errResult, nil
		}
		slog.Info("tool call", "backend", b.name, "tool", originalName, "user_id", userID)
		var args any
		if len(req.Params.Arguments) > 0 {
			args = req.Params.Arguments
		}

		start := time.Now()
		result, callErr := sess.CallTool(ctx, &mcp.CallToolParams{
			Name:      originalName,
			Arguments: args,
			Meta:      req.Params.Meta,
		})
		// If the upstream returned a transport-level 401, drop the cached
		// session so the next call re-dials with a fresh token. We do not
		// auto-retry — the next user attempt will resolve cleanly.
		if callErr != nil && b.authType == config.AuthTypeOAuth && isAuthError(callErr) {
			b.invalidateUserSession(userID)
		}
		b.recordCall(originalName, userID, start, args, result, callErr)
		return result, callErr
	}
}

// resolveSession returns the live session for this call, or a structured
// tool-error result describing how to authorize when tokens are missing.
// A non-nil err is a transport/infrastructure problem the SDK should surface
// as a protocol error; a non-nil errResult is a user-facing tool error.
func (g *Gateway) resolveSession(ctx context.Context, b *backend, userID string) (sess *mcp.ClientSession, errResult *mcp.CallToolResult, err error) {
	if b.authType == config.AuthTypeStatic {
		b.mu.RLock()
		s := b.sharedSession
		state := b.state
		b.mu.RUnlock()
		if state != StateConnected || s == nil {
			return nil, nil, fmt.Errorf("backend %q is currently unavailable", b.name)
		}
		return s, nil, nil
	}
	if userID == "" {
		return nil, errorResult("agentsmith: tool call has no associated user — auth middleware misconfigured"), nil
	}
	sess, err = g.dialUserSession(ctx, b, userID)
	if errors.Is(err, secrets.ErrNotFound) {
		return nil, g.connectPromptResult(b.name, userID), nil
	}
	if err != nil {
		return nil, errorResult(fmt.Sprintf("agentsmith: dial %s: %v", b.name, err)), nil
	}
	return sess, nil, nil
}

// connectPromptResult builds the structured tool-error result that points the
// user at the URL they need to visit to complete OAuth.
func (g *Gateway) connectPromptResult(backendName, userID string) *mcp.CallToolResult {
	if g.deps.Tickets == nil {
		return errorResult(fmt.Sprintf("Connect %s required, but ticket signer not configured", backendName))
	}
	ticket, err := g.deps.Tickets.Sign(userID, backendName, connectTicketTTL)
	if err != nil {
		return errorResult(fmt.Sprintf("sign connect ticket: %v", err))
	}
	base := g.deps.CallbackBaseURL
	if base == "" {
		base = "http://localhost:3002" // best-effort; operator should set CallbackBaseURL
	}
	url := oauth.BuildConnectURL(base, backendName, ticket)
	return errorResult(fmt.Sprintf("Connect your %s account first: %s", backendName, url))
}

// errorResult wraps a plaintext message as a structured tool-error result
// per the MCP spec — IsError=true so the LLM sees and surfaces it, content
// is a single TextContent block.
func errorResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}
}

// isAuthError is a heuristic test for "upstream rejected our credentials".
// The MCP SDK does not expose HTTP status codes through CallTool errors, so
// we string-match on the error message — good enough to trigger a re-dial
// without false-positive harm (worst case is an extra dial on the next call).
func isAuthError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "401") || strings.Contains(strings.ToLower(msg), "unauthorized")
}

// userIDFromContext returns the user ID attached by the identity middleware,
// or "" if none.
func userIDFromContext(ctx context.Context) string {
	u := identity.FromContext(ctx)
	if u == nil {
		return ""
	}
	return u.ID
}

// recordCall appends a CallEntry to the ring buffer and updates metrics.
func (b *backend) recordCall(tool, userID string, start time.Time, args any, result *mcp.CallToolResult, callErr error) {
	ms := time.Since(start).Milliseconds()
	e := CallEntry{
		ToolName:   tool,
		UserID:     userID,
		CalledAt:   start,
		DurationMs: ms,
		Success:    callErr == nil && (result == nil || !result.IsError),
		Request:    prettyJSON(args),
		Response:   prettyJSON(result),
	}
	if callErr != nil {
		e.Error = callErr.Error()
	}

	b.mu.Lock()
	// ring buffer write
	b.logBuf[b.logHead] = e
	b.logHead = (b.logHead + 1) % logCap
	if b.logCount < logCap {
		b.logCount++
	}
	// metrics
	b.metrics.TotalCalls++
	b.metrics.TotalMs += ms
	if !e.Success {
		b.metrics.TotalErrors++
	}
	if b.metrics.PerTool == nil {
		b.metrics.PerTool = make(map[string]int64)
	}
	b.metrics.PerTool[tool]++
	subs := make([]chan CallEntry, len(b.logSubs))
	copy(subs, b.logSubs)
	b.mu.Unlock()

	// notify SSE subscribers outside the lock
	for _, ch := range subs {
		select {
		case ch <- e:
		default: // subscriber too slow — drop rather than block
		}
	}
}

// recentCalls returns the call log entries in reverse-chronological order
// (most recent first), up to logCap entries.
func (b *backend) recentCalls() []CallEntry {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.logCount == 0 {
		return nil
	}
	out := make([]CallEntry, b.logCount)
	for i := range b.logCount {
		// walk backwards from the last written slot
		idx := (b.logHead - 1 - i + logCap) % logCap
		out[i] = b.logBuf[idx]
	}
	return out
}

// metricsSnapshot returns a copy of the current metrics.
func (b *backend) metricsSnapshot() Metrics {
	b.mu.RLock()
	defer b.mu.RUnlock()
	pt := make(map[string]int64, len(b.metrics.PerTool))
	maps.Copy(pt, b.metrics.PerTool)
	return Metrics{
		TotalCalls:  b.metrics.TotalCalls,
		TotalErrors: b.metrics.TotalErrors,
		TotalMs:     b.metrics.TotalMs,
		PerTool:     pt,
	}
}

// subscribeLogs registers a channel to receive new CallEntry values and
// returns an unsubscribe function. The caller must drain the channel.
func (b *backend) subscribeLogs() (ch chan CallEntry, unsub func()) {
	ch = make(chan CallEntry, 32)
	b.mu.Lock()
	b.logSubs = append(b.logSubs, ch)
	b.mu.Unlock()
	unsub = func() {
		b.mu.Lock()
		for i, s := range b.logSubs {
			if s == ch {
				b.logSubs = append(b.logSubs[:i], b.logSubs[i+1:]...)
				break
			}
		}
		b.mu.Unlock()
	}
	return ch, unsub
}

// BackendByName returns a fully hydrated BackendDetail for the named backend,
// or false if no backend with that name exists.
func (g *Gateway) BackendByName(name string) (BackendDetail, bool) {
	b := g.backendByName(name)
	if b == nil {
		return BackendDetail{}, false
	}
	return b.detailSnapshot(), true
}

func (g *Gateway) backendByName(name string) *backend {
	for _, b := range g.backends {
		if b.name == name {
			return b
		}
	}
	return nil
}

// detailSnapshot builds a BackendDetail from the backend's current state.
func (b *backend) detailSnapshot() BackendDetail {
	base := b.snapshot() // acquires + releases RLock

	b.mu.RLock()
	toolsCopy := make([]*mcp.Tool, len(b.tools))
	copy(toolsCopy, b.tools)
	b.mu.RUnlock()

	infos := make([]ToolInfo, 0, len(toolsCopy))
	for _, t := range toolsCopy {
		infos = append(infos, toToolInfo(t))
	}
	return BackendDetail{
		BackendStatus: base,
		Tools:         infos,
		Metrics:       b.metricsSnapshot(),
		Log:           b.recentCalls(),
	}
}

// SubscribeLogs exposes the per-backend log subscription to the admin layer.
func (g *Gateway) SubscribeLogs(name string) (ch chan CallEntry, unsub func(), ok bool) {
	for _, b := range g.backends {
		if b.name == name {
			ch, unsub = b.subscribeLogs()
			return ch, unsub, true
		}
	}
	return nil, nil, false
}

// AggregateMetrics sums metrics across all backends for the dashboard summary.
func (g *Gateway) AggregateMetrics() Metrics {
	agg := Metrics{PerTool: make(map[string]int64)}
	for _, b := range g.backends {
		m := b.metricsSnapshot()
		agg.TotalCalls += m.TotalCalls
		agg.TotalErrors += m.TotalErrors
		agg.TotalMs += m.TotalMs
		for k, v := range m.PerTool {
			agg.PerTool[k] += v
		}
	}
	return agg
}

// toToolInfo converts an mcp.Tool into the display-friendly ToolInfo type.
func toToolInfo(t *mcp.Tool) ToolInfo {
	info := ToolInfo{
		Name:        t.Name,
		Title:       t.Title,
		Description: t.Description,
		InputSchema: prettyJSON(t.InputSchema),
		Params:      extractParams(t.InputSchema),
	}
	if t.OutputSchema != nil {
		info.OutputSchema = prettyJSON(t.OutputSchema)
	}
	if t.Annotations != nil {
		info.ReadOnly = t.Annotations.ReadOnlyHint
		info.Idempotent = t.Annotations.IdempotentHint
		info.Destructive = t.Annotations.DestructiveHint
		info.OpenWorld = t.Annotations.OpenWorldHint
	}
	return info
}

// extractParams parses the top-level properties of a JSON Schema object into
// a flat slice of ParamInfo for tabular display. Returns nil for schemas that
// have no top-level properties or cannot be parsed.
func extractParams(schema any) []ParamInfo {
	if schema == nil {
		return nil
	}
	data, err := json.Marshal(schema)
	if err != nil {
		return nil
	}
	var s struct {
		Properties map[string]struct {
			Type        string          `json:"type"`
			Description string          `json:"description"`
			Default     json.RawMessage `json:"default"`
		} `json:"properties"`
		Required []string `json:"required"`
	}
	if err := json.Unmarshal(data, &s); err != nil || len(s.Properties) == 0 {
		return nil
	}
	req := make(map[string]bool, len(s.Required))
	for _, r := range s.Required {
		req[r] = true
	}
	params := make([]ParamInfo, 0, len(s.Properties))
	for name, prop := range s.Properties {
		p := ParamInfo{
			Name:        name,
			Type:        prop.Type,
			Description: prop.Description,
			Required:    req[name],
		}
		if len(prop.Default) > 0 && string(prop.Default) != "null" {
			p.Default = string(prop.Default)
		}
		params = append(params, p)
	}
	// Required params first, then alphabetical.
	sort.Slice(params, func(i, j int) bool {
		if params[i].Required != params[j].Required {
			return params[i].Required
		}
		return params[i].Name < params[j].Name
	})
	return params
}

// prettyJSON marshals v to indented JSON. Returns an empty string on error.
func prettyJSON(v any) string {
	if v == nil {
		return ""
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return ""
	}
	return string(data)
}

// SplitNamespacedTool reverses the namespacing applied at registration.
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

// RoundTrip injects this target's headers and forwards the request to the
// underlying transport. Per-target headers never leak across backends.
func (h *headerInjector) RoundTrip(req *http.Request) (*http.Response, error) {
	for k, v := range h.headers {
		req.Header.Set(k, v)
	}
	return h.base.RoundTrip(req)
}
