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
)

func TestNewPKCE_Produces_S256Pair(t *testing.T) {
	p, err := NewPKCE()
	if err != nil {
		t.Fatalf("NewPKCE: %v", err)
	}
	if p.Method != "S256" {
		t.Errorf("method = %q, want S256", p.Method)
	}
	sum := sha256.Sum256([]byte(p.Verifier))
	expect := base64.RawURLEncoding.EncodeToString(sum[:])
	if p.Challenge != expect {
		t.Errorf("challenge does not match sha256(verifier)")
	}
}

func TestAuthCodeURL_ContainsPKCEAndState(t *testing.T) {
	ep := &Endpoints{AuthorizationURL: "https://as.example/authorize"}
	u := AuthCodeURL(ep, "cid", "https://cb.example/callback", "STATE", PKCE{
		Verifier:  "v",
		Challenge: "CHAL",
		Method:    "S256",
	}, []string{"chat:write", "channels:read"})
	parsed, err := url.Parse(u)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	q := parsed.Query()
	if q.Get("client_id") != "cid" {
		t.Errorf("client_id = %q", q.Get("client_id"))
	}
	if q.Get("code_challenge") != "CHAL" || q.Get("code_challenge_method") != "S256" {
		t.Errorf("missing PKCE: %v", q)
	}
	if q.Get("state") != "STATE" {
		t.Errorf("state = %q", q.Get("state"))
	}
	if q.Get("scope") != "chat:write channels:read" {
		t.Errorf("scope = %q", q.Get("scope"))
	}
	if q.Get("redirect_uri") != "https://cb.example/callback" {
		t.Errorf("redirect_uri = %q", q.Get("redirect_uri"))
	}
}

func TestExchangeCode_PostsFormAndParsesTokens(t *testing.T) {
	var seenForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		seenForm = r.PostForm
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "AT",
			"refresh_token": "RT",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"scope":         "chat:write",
		})
	}))
	defer srv.Close()

	ep := &Endpoints{TokenURL: srv.URL}
	tok, err := ExchangeCode(context.Background(), ep, "cid", "csecret", "thecode", "theverifier", "https://cb.example/x")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if tok.AccessToken != "AT" || tok.RefreshToken != "RT" {
		t.Errorf("tokens = %+v", tok)
	}
	if tok.ExpiresAt.IsZero() {
		t.Error("expires_at not populated")
	}
	if seenForm.Get("code") != "thecode" {
		t.Errorf("form code = %q", seenForm.Get("code"))
	}
	if seenForm.Get("code_verifier") != "theverifier" {
		t.Errorf("form code_verifier = %q", seenForm.Get("code_verifier"))
	}
	if seenForm.Get("grant_type") != "authorization_code" {
		t.Errorf("grant_type = %q", seenForm.Get("grant_type"))
	}
}

func TestExchangeCode_NonOKStatusIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
	}))
	defer srv.Close()

	ep := &Endpoints{TokenURL: srv.URL}
	_, err := ExchangeCode(context.Background(), ep, "cid", "", "code", "v", "redir")
	if err == nil {
		t.Fatal("expected error on 400")
	}
	if !strings.Contains(err.Error(), "invalid_grant") {
		t.Errorf("error should surface upstream body, got: %v", err)
	}
}

func TestRefresh_SendsRefreshTokenAndParses(t *testing.T) {
	var seenForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		seenForm = r.PostForm
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "AT2",
			"expires_in":   60,
		})
	}))
	defer srv.Close()

	ep := &Endpoints{TokenURL: srv.URL}
	tok, err := Refresh(context.Background(), ep, "cid", "", "oldrt")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if tok.AccessToken != "AT2" {
		t.Errorf("access = %q", tok.AccessToken)
	}
	if seenForm.Get("grant_type") != "refresh_token" {
		t.Errorf("grant_type = %q", seenForm.Get("grant_type"))
	}
	if seenForm.Get("refresh_token") != "oldrt" {
		t.Errorf("refresh_token = %q", seenForm.Get("refresh_token"))
	}
}

func TestExchangeCode_EmptyAccessTokenIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"expires_in": 3600})
	}))
	defer srv.Close()

	ep := &Endpoints{TokenURL: srv.URL}
	_, err := ExchangeCode(context.Background(), ep, "cid", "", "code", "v", "redir")
	if err == nil {
		t.Fatal("expected error on empty access_token")
	}
}
