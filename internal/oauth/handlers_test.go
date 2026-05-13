package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/sebastienmelki/agentsmith/internal/secrets"
)

// newTestHandler builds a Handler wired to fresh in-memory stores and a
// signer using a test key. The upstream token endpoint is a fake provided
// by the caller so each test can assert/respond on its own terms.
func newTestHandler(t *testing.T, tokenURL string) *Handler {
	t.Helper()
	signer, err := NewTicketSigner("test-key-must-be-long-enough-1234")
	if err != nil {
		t.Fatalf("NewTicketSigner: %v", err)
	}
	reg := NewRegistry()
	reg.Set(&BackendConfig{
		Name:         "slack",
		ClientID:     "cid",
		ClientSecret: "csecret",
		Scopes:       []string{"chat:write"},
		Endpoints: &Endpoints{
			AuthorizationURL: "https://as.example/authorize",
			TokenURL:         tokenURL,
		},
	})
	return New(HandlerDeps{
		Tickets:  signer,
		Tokens:   secrets.NewMemoryTokenStore(),
		Registry: reg,
	})
}

func TestHandleConnect_HappyPathRedirects(t *testing.T) {
	h := newTestHandler(t, "https://unused")
	ticket, err := h.deps.Tickets.Sign("alice", "slack", 5*time.Minute)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"http://gateway.example.com/oauth/connect/slack?ticket="+url.QueryEscape(ticket), http.NoBody)
	rr := httptest.NewRecorder()
	h.HandleConnect(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://as.example/authorize?") {
		t.Errorf("Location = %q", loc)
	}
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("Parse Location: %v", err)
	}
	q := parsed.Query()
	if q.Get("client_id") != "cid" || q.Get("code_challenge") == "" || q.Get("state") == "" {
		t.Errorf("authz URL missing required params: %v", q)
	}
	if got := q.Get("redirect_uri"); got != "http://gateway.example.com/oauth/callback/slack" {
		t.Errorf("redirect_uri = %q", got)
	}
}

func TestHandleConnect_MissingTicketRejected(t *testing.T) {
	h := newTestHandler(t, "https://unused")
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"http://gateway/oauth/connect/slack", http.NoBody)
	rr := httptest.NewRecorder()
	h.HandleConnect(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

func TestHandleConnect_TicketBackendMismatchRejected(t *testing.T) {
	h := newTestHandler(t, "https://unused")
	ticket, _ := h.deps.Tickets.Sign("alice", "github", time.Minute)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"http://gateway/oauth/connect/slack?ticket="+url.QueryEscape(ticket), http.NoBody)
	rr := httptest.NewRecorder()
	h.HandleConnect(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestHandleCallback_HappyPathPersistsTokens(t *testing.T) {
	// Stand up a fake upstream token endpoint.
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "AT",
			"refresh_token": "RT",
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	}))
	defer tokenSrv.Close()

	h := newTestHandler(t, tokenSrv.URL)

	// Run a real connect to populate the state store.
	ticket, _ := h.deps.Tickets.Sign("alice", "slack", time.Minute)
	connectReq := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"http://gateway/oauth/connect/slack?ticket="+url.QueryEscape(ticket), http.NoBody)
	connectRR := httptest.NewRecorder()
	h.HandleConnect(connectRR, connectReq)
	if connectRR.Code != http.StatusFound {
		t.Fatalf("connect status = %d", connectRR.Code)
	}
	loc, _ := url.Parse(connectRR.Header().Get("Location"))
	state := loc.Query().Get("state")
	if state == "" {
		t.Fatal("no state issued")
	}

	cbReq := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"http://gateway/oauth/callback/slack?state="+state+"&code=THECODE", http.NoBody)
	cbRR := httptest.NewRecorder()
	h.HandleCallback(cbRR, cbReq)

	if cbRR.Code != http.StatusOK {
		t.Fatalf("callback status = %d, body=%s", cbRR.Code, cbRR.Body.String())
	}
	tok, err := h.deps.Tokens.Get("alice", "slack")
	if err != nil {
		t.Fatalf("Get tokens: %v", err)
	}
	if tok.AccessToken != "AT" || tok.RefreshToken != "RT" {
		t.Errorf("persisted tokens = %+v", tok)
	}
}

func TestHandleCallback_UnknownStateRejected(t *testing.T) {
	h := newTestHandler(t, "https://unused")
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"http://gateway/oauth/callback/slack?state=nope&code=x", http.NoBody)
	rr := httptest.NewRecorder()
	h.HandleCallback(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestHandleCallback_UpstreamErrorSurfaces(t *testing.T) {
	h := newTestHandler(t, "https://unused")
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"http://gateway/oauth/callback/slack?error=access_denied&error_description=user+rejected", http.NoBody)
	rr := httptest.NewRecorder()
	h.HandleCallback(rr, req)
	if !strings.Contains(rr.Body.String(), "access_denied") {
		t.Errorf("body did not include upstream error: %s", rr.Body.String())
	}
}

func TestDeriveBaseURL_HonoursForwardedHeaders(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://internal/x", http.NoBody)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "gateway.acme.com")
	if got := deriveBaseURL(req); got != "https://gateway.acme.com" {
		t.Errorf("deriveBaseURL = %q", got)
	}
}

func TestBuildConnectURL(t *testing.T) {
	got := BuildConnectURL("https://gateway.acme.com/", "slack", "TICKET")
	want := "https://gateway.acme.com/oauth/connect/slack?ticket=TICKET"
	if got != want {
		t.Errorf("BuildConnectURL = %q, want %q", got, want)
	}
}

func TestStateStore_SingleUse(t *testing.T) {
	s := newStateStore()
	s.put("k", &stateEntry{Expires: time.Now().Add(time.Minute)})
	if s.take("k") == nil {
		t.Fatal("first take should succeed")
	}
	if s.take("k") != nil {
		t.Fatal("second take should be nil — state is single-use")
	}
}

func TestStateStore_ExpiredDropped(t *testing.T) {
	s := newStateStore()
	s.put("k", &stateEntry{Expires: time.Now().Add(-time.Second)})
	if s.take("k") != nil {
		t.Fatal("expired state should not be returned")
	}
}
