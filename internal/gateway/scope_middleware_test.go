package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sebastienmelki/agentsmith/internal/config"
	"github.com/sebastienmelki/agentsmith/internal/identity"
	"github.com/sebastienmelki/agentsmith/internal/oauth"
	"github.com/sebastienmelki/agentsmith/internal/secrets"
)

// newScopeTestGateway returns a Gateway minimally populated for the scope
// middleware: one static backend ("dodo"), one OAuth backend ("worldmonitor"),
// and a token store the test can pre-seed to simulate "user already OAuthed
// this backend."
func newScopeTestGateway(t *testing.T, tokens *secrets.RefreshingTokenStore) *Gateway {
	t.Helper()
	cfg := &config.Config{
		AuthMode: config.ModeUnprotected,
		Targets: []config.Target{
			{Name: "dodo", URL: "http://127.0.0.1:1/mcp"},
			{Name: "worldmonitor", URL: "http://127.0.0.1:2/mcp", Auth: &config.TargetAuth{Type: config.AuthTypeOAuth}},
		},
	}
	gw, err := New(context.Background(), cfg, Deps{Tokens: tokens})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	t.Cleanup(gw.Close)
	return gw
}

// jsonRPCRequest builds a synthetic JSON-RPC body wrapped as an HTTP POST. The
// scope middleware reads only the body, so any URL works.
func jsonRPCRequest(method, toolName string) *http.Request {
	body := `{"jsonrpc":"2.0","id":1,"method":"` + method + `"`
	if toolName != "" {
		body += `,"params":{"name":"` + toolName + `"}`
	}
	body += `}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"http://gateway/mcp", strings.NewReader(body))
	// Attach the default user so the middleware doesn't bail on missing identity.
	ctx := identity.WithUser(req.Context(), &identity.User{ID: identity.DefaultUserID})
	return req.WithContext(ctx)
}

// TestScopeMiddleware_StaticToolPassesThrough confirms tools/call to a
// static-typed backend skips the 401 entirely — that's the whole UX win.
func TestScopeMiddleware_StaticToolPassesThrough(t *testing.T) {
	gw := newScopeTestGateway(t, secrets.NewRefreshingTokenStore(secrets.NewMemoryTokenStore(), nil))
	called := false
	h := gw.ScopeMiddleware(nil)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true }))

	req := jsonRPCRequest("tools/call", "dodo__create_payment")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !called {
		t.Errorf("static tool: code=%d called=%v, want 200 + called", rr.Code, called)
	}
}

// TestScopeMiddleware_OAuthBackendWithoutTokensReturns401 confirms a tool call
// to an OAuth backend the user hasn't authorized produces the
// insufficient_scope challenge that opens the browser.
func TestScopeMiddleware_OAuthBackendWithoutTokensReturns401(t *testing.T) {
	gw := newScopeTestGateway(t, secrets.NewRefreshingTokenStore(secrets.NewMemoryTokenStore(), nil))
	h := gw.ScopeMiddleware(func(_ *http.Request) string {
		return "http://gateway/.well-known/oauth-protected-resource"
	})(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("inner handler should not run for an OAuth tool with no tokens")
	}))

	req := jsonRPCRequest("tools/call", "worldmonitor__news")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	challenge := rr.Header().Get("WWW-Authenticate")
	if !strings.Contains(challenge, `scope="worldmonitor:*"`) {
		t.Errorf("challenge missing scope: %q", challenge)
	}
	if !strings.Contains(challenge, "insufficient_scope") {
		t.Errorf("challenge missing insufficient_scope: %q", challenge)
	}
	if !strings.Contains(challenge, "resource_metadata=") {
		t.Errorf("challenge missing resource_metadata: %q", challenge)
	}
}

// TestScopeMiddleware_OAuthBackendWithTokensPassesThrough confirms that once
// upstream tokens exist for (user, backend), the tool call passes through —
// no re-OAuth prompt for already-connected backends.
func TestScopeMiddleware_OAuthBackendWithTokensPassesThrough(t *testing.T) {
	mem := secrets.NewMemoryTokenStore()
	_ = mem.Save(identity.DefaultUserID, "worldmonitor", &secrets.Tokens{AccessToken: "AT"})
	tokens := secrets.NewRefreshingTokenStore(mem, nil)
	gw := newScopeTestGateway(t, tokens)

	called := false
	h := gw.ScopeMiddleware(nil)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true }))

	req := jsonRPCRequest("tools/call", "worldmonitor__news")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !called {
		t.Errorf("authorized OAuth tool: code=%d called=%v", rr.Code, called)
	}
}

// TestScopeMiddleware_ToolsListPassesThrough confirms tools/list (catalog
// discovery) never triggers OAuth even with OAuth backends configured. That's
// how clients can see what's available before consenting.
func TestScopeMiddleware_ToolsListPassesThrough(t *testing.T) {
	gw := newScopeTestGateway(t, secrets.NewRefreshingTokenStore(secrets.NewMemoryTokenStore(), nil))
	called := false
	h := gw.ScopeMiddleware(nil)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true }))

	req := jsonRPCRequest("tools/list", "")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !called {
		t.Errorf("tools/list: code=%d called=%v, want 200 + called", rr.Code, called)
	}
}

// TestScopeMiddleware_MalformedJSONFallsThrough confirms the middleware never
// breaks the request path on a non-JSON or otherwise unparseable body — it
// hands the request to the inner handler unchanged and lets the SDK respond.
func TestScopeMiddleware_MalformedJSONFallsThrough(t *testing.T) {
	gw := newScopeTestGateway(t, secrets.NewRefreshingTokenStore(secrets.NewMemoryTokenStore(), nil))
	called := false
	h := gw.ScopeMiddleware(nil)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true }))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"http://gateway/mcp", strings.NewReader("not json"))
	req = req.WithContext(identity.WithUser(req.Context(), &identity.User{ID: identity.DefaultUserID}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !called {
		t.Errorf("malformed body: code=%d called=%v", rr.Code, called)
	}
}

// TestScopeMiddleware_UnknownBackendFallsThrough confirms calls to a tool
// whose backend isn't in the registry pass through unchanged — the SDK turns
// that into a tool-not-found response. The scope middleware does not own
// "unknown backend" semantics.
func TestScopeMiddleware_UnknownBackendFallsThrough(t *testing.T) {
	gw := newScopeTestGateway(t, secrets.NewRefreshingTokenStore(secrets.NewMemoryTokenStore(), nil))
	called := false
	h := gw.ScopeMiddleware(nil)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true }))

	req := jsonRPCRequest("tools/call", "ghost__foo")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !called {
		t.Errorf("unknown backend: code=%d called=%v", rr.Code, called)
	}
}

// Compile-time check that the oauth import is exercised — keeps a single
// import-of-record so test packages depending on the same wiring don't drift.
var _ = oauth.BackendScope
