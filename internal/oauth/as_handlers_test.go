package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/sebastienmelki/agentsmith/internal/secrets"
)

// newASHandler builds a Handler with the AS plumbing wired up plus one fake
// OAuth backend whose authorization endpoint is configurable. The token
// endpoint URL passed in is what the gateway will POST to during /callback.
// Backend name is fixed to "slack" so every test exercises the same scope
// shape; that's intentional, not a missing parameter.
func newASHandler(t *testing.T, authURL, tokenURL string) *Handler {
	t.Helper()
	const backend = "slack"
	signer, err := NewTicketSigner("test-key-must-be-long-enough-1234")
	if err != nil {
		t.Fatalf("NewTicketSigner: %v", err)
	}
	reg := NewRegistry()
	reg.Set(&BackendConfig{
		Name:         backend,
		ClientID:     "upstream-cid",
		ClientSecret: "upstream-secret",
		Scopes:       []string{"chat:write"},
		Endpoints: &Endpoints{
			AuthorizationURL: authURL,
			TokenURL:         tokenURL,
		},
	})
	return New(HandlerDeps{
		Tickets:          signer,
		Tokens:           secrets.NewMemoryTokenStore(),
		Registry:         reg,
		Clients:          NewClientStore(),
		Codes:            NewCodeStore(),
		IssuedTokens:     NewASTokenStore(),
		Sessions:         NewSessionStore(),
		OAuthBackends:    []string{backend},
		IdentityResolver: FixedUserIdentity("alice"),
	})
}

func TestHandleProtectedResource_AdvertisesBackendScopes(t *testing.T) {
	h := newASHandler(t, "https://upstream/authorize", "https://upstream/token")
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"http://gateway/.well-known/oauth-protected-resource", http.NoBody)
	rr := httptest.NewRecorder()
	h.HandleProtectedResource(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var doc ProtectedResourceMetadata
	if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if doc.Resource != "http://gateway/mcp" {
		t.Errorf("resource = %q", doc.Resource)
	}
	if len(doc.AuthorizationServers) != 1 || doc.AuthorizationServers[0] != "http://gateway" {
		t.Errorf("authorization_servers = %v", doc.AuthorizationServers)
	}
	if len(doc.ScopesSupported) != 1 || doc.ScopesSupported[0] != "slack:*" {
		t.Errorf("scopes_supported = %v", doc.ScopesSupported)
	}
}

func TestHandleAuthorizationServer_AdvertisesEndpoints(t *testing.T) {
	h := newASHandler(t, "https://u/authorize", "https://u/token")
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"http://gateway/.well-known/oauth-authorization-server", http.NoBody)
	rr := httptest.NewRecorder()
	h.HandleAuthorizationServer(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var doc AuthorizationServerMetadata
	if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if doc.AuthorizationEndpoint != "http://gateway/oauth/authorize" {
		t.Errorf("authorize endpoint = %q", doc.AuthorizationEndpoint)
	}
	if doc.TokenEndpoint != "http://gateway/oauth/token" {
		t.Errorf("token endpoint = %q", doc.TokenEndpoint)
	}
	if doc.RegistrationEndpoint != "http://gateway/oauth/register" {
		t.Errorf("registration endpoint = %q", doc.RegistrationEndpoint)
	}
	wantsS256 := false
	for _, m := range doc.CodeChallengeMethodsSupported {
		if m == "S256" {
			wantsS256 = true
		}
	}
	if !wantsS256 {
		t.Errorf("S256 not advertised in code_challenge_methods_supported")
	}
}

func TestHandleRegister_HappyPath(t *testing.T) {
	h := newASHandler(t, "https://u/authorize", "https://u/token")
	body := `{"client_name":"ClaudeCode","redirect_uris":["http://localhost:1234/cb"]}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"http://gateway/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.HandleRegister(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := resp["client_id"].(string); !ok {
		t.Errorf("no client_id in response: %v", resp)
	}
}

func TestHandleRegister_RejectsMissingRedirectURIs(t *testing.T) {
	h := newASHandler(t, "https://u/authorize", "https://u/token")
	body := `{"client_name":"x"}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"http://gateway/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.HandleRegister(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestHandleAuthorize_UnknownClientReturns400(t *testing.T) {
	h := newASHandler(t, "https://u/authorize", "https://u/token")
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"http://gateway/oauth/authorize?response_type=code&client_id=bogus&redirect_uri=http://x/cb&code_challenge=c&code_challenge_method=S256",
		http.NoBody)
	rr := httptest.NewRecorder()
	h.HandleAuthorize(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestHandleAuthorize_RedirectMismatchReturns400(t *testing.T) {
	h := newASHandler(t, "https://u/authorize", "https://u/token")
	client, _ := h.deps.Clients.Register("x", []string{"http://localhost:1234/cb"})
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", client.ID)
	q.Set("redirect_uri", "http://attacker/cb")
	q.Set("code_challenge", "c")
	q.Set("code_challenge_method", "S256")
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"http://gateway/oauth/authorize?"+q.Encode(), http.NoBody)
	rr := httptest.NewRecorder()
	h.HandleAuthorize(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (redirect_uri mismatch must not redirect)", rr.Code)
	}
}

// TestHandleAuthorize_ChainsThroughUpstream confirms that with no upstream
// tokens on file the gateway 302s the browser to the upstream's authorization
// endpoint and stashes a session for the eventual callback.
func TestHandleAuthorize_ChainsThroughUpstream(t *testing.T) {
	h := newASHandler(t, "https://upstream/authorize", "https://upstream/token")
	client, _ := h.deps.Clients.Register("x", []string{"http://localhost:1234/cb"})
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", client.ID)
	q.Set("redirect_uri", "http://localhost:1234/cb")
	q.Set("scope", "slack:*")
	q.Set("state", "client-state")
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"http://gateway/oauth/authorize?"+q.Encode(), http.NoBody)
	rr := httptest.NewRecorder()
	h.HandleAuthorize(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d (want 302 to upstream)", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://upstream/authorize?") {
		t.Errorf("expected redirect to upstream, got %q", loc)
	}
}

// TestEndToEnd_FullChain walks register → authorize → upstream callback →
// token, verifying the gateway issues a real bearer at the end.
func TestEndToEnd_FullChain(t *testing.T) {
	upstreamToken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "upstream-at",
			"refresh_token": "upstream-rt",
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	}))
	defer upstreamToken.Close()

	h := newASHandler(t, "https://upstream/authorize", upstreamToken.URL)

	// 1. Register a client.
	client, _ := h.deps.Clients.Register("ClaudeCode", []string{"http://localhost:1234/cb"})

	// 2. Build a /authorize request with a real PKCE pair.
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	authQ := url.Values{}
	authQ.Set("response_type", "code")
	authQ.Set("client_id", client.ID)
	authQ.Set("redirect_uri", "http://localhost:1234/cb")
	authQ.Set("scope", "slack:*")
	authQ.Set("state", "client-state")
	authQ.Set("code_challenge", challenge)
	authQ.Set("code_challenge_method", "S256")
	authReq := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"http://gateway/oauth/authorize?"+authQ.Encode(), http.NoBody)
	authRR := httptest.NewRecorder()
	h.HandleAuthorize(authRR, authReq)
	if authRR.Code != http.StatusFound {
		t.Fatalf("/authorize status = %d", authRR.Code)
	}
	upstreamLoc, err := url.Parse(authRR.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse upstream redirect: %v", err)
	}
	upstreamState := upstreamLoc.Query().Get("state")
	if upstreamState == "" {
		t.Fatal("upstream redirect missing state")
	}

	// 3. Simulate the upstream completing OAuth and redirecting to our callback.
	cbReq := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"http://gateway/oauth/callback/slack?state="+upstreamState+"&code=upstream-code", http.NoBody)
	cbRR := httptest.NewRecorder()
	h.HandleCallback(cbRR, cbReq)
	if cbRR.Code != http.StatusFound {
		t.Fatalf("/callback status = %d, body=%s", cbRR.Code, cbRR.Body.String())
	}
	clientRedirect, err := url.Parse(cbRR.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse client redirect: %v", err)
	}
	if clientRedirect.Host != "localhost:1234" {
		t.Errorf("final redirect host = %q, want localhost:1234", clientRedirect.Host)
	}
	code := clientRedirect.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in client redirect: %s", clientRedirect.String())
	}
	if got := clientRedirect.Query().Get("state"); got != "client-state" {
		t.Errorf("client state = %q, want client-state", got)
	}

	// 4. Exchange the code at /token with the matching verifier.
	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("code", code)
	tokenForm.Set("client_id", client.ID)
	tokenForm.Set("redirect_uri", "http://localhost:1234/cb")
	tokenForm.Set("code_verifier", verifier)
	tokenReq := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"http://gateway/oauth/token", strings.NewReader(tokenForm.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRR := httptest.NewRecorder()
	h.HandleToken(tokenRR, tokenReq)
	if tokenRR.Code != http.StatusOK {
		t.Fatalf("/token status = %d, body=%s", tokenRR.Code, tokenRR.Body.String())
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		Scope        string `json:"scope"`
	}
	if err := json.Unmarshal(tokenRR.Body.Bytes(), &tokenResp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if tokenResp.AccessToken == "" || tokenResp.RefreshToken == "" {
		t.Errorf("token response missing fields: %+v", tokenResp)
	}
	if tokenResp.TokenType != "Bearer" {
		t.Errorf("token_type = %q", tokenResp.TokenType)
	}
	if tokenResp.ExpiresIn <= 0 {
		t.Errorf("expires_in = %d", tokenResp.ExpiresIn)
	}

	// 5. The bearer should resolve back to alice/slack:* via LookupBearerToken.
	userID, scopes, ok := h.LookupBearerToken(tokenResp.AccessToken)
	if !ok {
		t.Fatal("LookupBearerToken returned !ok")
	}
	if userID != "alice" {
		t.Errorf("userID = %q, want alice", userID)
	}
	if len(scopes) != 1 || scopes[0] != "slack:*" {
		t.Errorf("scopes = %v", scopes)
	}

	// 6. Upstream tokens must be persisted under the user — that's the whole
	//    point of the chain.
	upstream, err := h.deps.Tokens.Get("alice", "slack")
	if err != nil {
		t.Fatalf("upstream Tokens.Get: %v", err)
	}
	if upstream.AccessToken != "upstream-at" {
		t.Errorf("upstream access token = %q", upstream.AccessToken)
	}
}

func TestHandleToken_RejectsPKCEMismatch(t *testing.T) {
	h := newASHandler(t, "https://u/authorize", "https://u/token")
	verifier := "real-verifier"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	h.deps.Codes.put(&authorizationCode{
		Code:                "abc",
		ClientID:            "c1",
		UserID:              "alice",
		RedirectURI:         "http://localhost/cb",
		Scopes:              []string{"slack:*"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		Expires:             time.Now().Add(time.Minute),
	})
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", "abc")
	form.Set("client_id", "c1")
	form.Set("redirect_uri", "http://localhost/cb")
	form.Set("code_verifier", "wrong-verifier") // intentionally bad
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"http://gateway/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.HandleToken(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 invalid_grant", rr.Code)
	}
}

func TestHandleToken_RefreshGrantRotates(t *testing.T) {
	h := newASHandler(t, "https://u/authorize", "https://u/token")
	tok, _ := h.deps.IssuedTokens.Issue("c1", "alice", []string{"slack:*"})

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", tok.RefreshToken)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"http://gateway/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.HandleToken(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["access_token"] == tok.AccessToken {
		t.Error("rotation did not produce a fresh access token")
	}
}

func TestBackendFromScope(t *testing.T) {
	cases := []struct {
		in     string
		want   string
		wantOK bool
	}{
		{"slack:*", "slack", true},
		{"dodo:*", "dodo", true},
		{"slack:read", "", false},
		{"slack", "", false},
		{":*", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := backendFromScope(c.in)
		if got != c.want || ok != c.wantOK {
			t.Errorf("backendFromScope(%q) = (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.wantOK)
		}
	}
}

func TestParseScopes_Deduplicates(t *testing.T) {
	got := parseScopes("slack:* dodo:* slack:*  ")
	if len(got) != 2 {
		t.Fatalf("parseScopes = %v, want 2 entries", got)
	}
	if got[0] != "slack:*" || got[1] != "dodo:*" {
		t.Errorf("parseScopes returned %v", got)
	}
}
