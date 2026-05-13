package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sebastienmelki/agentsmith/internal/secrets"
)

// httpClient is the HTTP client used for token exchanges and refreshes.
// Overridden in tests.
var httpClient = &http.Client{Timeout: 30 * time.Second}

// PKCE bundles a code verifier and its challenge. We keep the verifier on the
// server side (in pendingState) and send only the challenge to the
// authorization server; on callback we send the verifier with the code so
// the token endpoint can prove the same client started the flow.
type PKCE struct {
	Verifier  string
	Challenge string
	Method    string // always "S256"
}

// NewPKCE generates a fresh code_verifier/code_challenge pair per RFC 7636.
func NewPKCE() (PKCE, error) {
	v, err := randURLSafe(64)
	if err != nil {
		return PKCE{}, err
	}
	sum := sha256.Sum256([]byte(v))
	c := base64.RawURLEncoding.EncodeToString(sum[:])
	return PKCE{Verifier: v, Challenge: c, Method: "S256"}, nil
}

// RandomState returns a fresh URL-safe state token used to bind the
// authorization request to its callback.
func RandomState() (string, error) { return randURLSafe(32) }

// AuthCodeURL builds the URL the browser is redirected to so the user can
// approve the requested scopes. State and PKCE values must be stashed
// server-side so the callback can complete the exchange.
func AuthCodeURL(endpoints *Endpoints, clientID, redirectURI, state string, pkce PKCE, scopes []string) string {
	v := url.Values{}
	v.Set("response_type", "code")
	v.Set("client_id", clientID)
	v.Set("redirect_uri", redirectURI)
	v.Set("state", state)
	v.Set("code_challenge", pkce.Challenge)
	v.Set("code_challenge_method", pkce.Method)
	if len(scopes) > 0 {
		v.Set("scope", strings.Join(scopes, " "))
	}
	sep := "?"
	if strings.Contains(endpoints.AuthorizationURL, "?") {
		sep = "&"
	}
	return endpoints.AuthorizationURL + sep + v.Encode()
}

// ExchangeCode swaps an authorization code for an access token + refresh
// token at the upstream's token endpoint. clientSecret may be empty for
// public clients.
func ExchangeCode(ctx context.Context, endpoints *Endpoints, clientID, clientSecret, code, codeVerifier, redirectURI string) (*secrets.Tokens, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", clientID)
	form.Set("code_verifier", codeVerifier)
	return tokenPost(ctx, endpoints.TokenURL, clientID, clientSecret, form)
}

// Refresh exchanges a refresh token for a new access token. Some providers
// rotate the refresh token; callers persist whatever is returned.
func Refresh(ctx context.Context, endpoints *Endpoints, clientID, clientSecret, refreshToken string) (*secrets.Tokens, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", clientID)
	return tokenPost(ctx, endpoints.TokenURL, clientID, clientSecret, form)
}

// tokenPost performs a POST to the token endpoint and parses the response into
// secrets.Tokens. clientSecret, when non-empty, is sent via HTTP Basic auth
// per RFC 6749 §2.3.1.
func tokenPost(ctx context.Context, tokenURL, clientID, clientSecret string, form url.Values) (*secrets.Tokens, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if clientSecret != "" {
		req.SetBasicAuth(clientID, clientSecret)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauth: post %s: %w", tokenURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("oauth: token endpoint %s: status %d: %s", tokenURL, resp.StatusCode, snippet(body))
	}
	var raw struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("oauth: parse token response: %w (body: %s)", err, snippet(body))
	}
	if raw.AccessToken == "" {
		return nil, fmt.Errorf("oauth: token endpoint returned empty access_token (body: %s)", snippet(body))
	}
	tok := &secrets.Tokens{
		AccessToken:  raw.AccessToken,
		RefreshToken: raw.RefreshToken,
		TokenType:    raw.TokenType,
	}
	if raw.ExpiresIn > 0 {
		tok.ExpiresAt = time.Now().UTC().Add(time.Duration(raw.ExpiresIn) * time.Second)
	}
	if raw.Scope != "" {
		tok.Scopes = strings.Fields(raw.Scope)
	}
	return tok, nil
}

// snippet trims a response body for inclusion in error messages.
func snippet(b []byte) string {
	const maxLen = 256
	if len(b) > maxLen {
		return string(b[:maxLen]) + "…"
	}
	return string(b)
}

// randURLSafe returns a URL-safe (unpadded base64) random string with at
// least n bytes of entropy.
func randURLSafe(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
