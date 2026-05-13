package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// discoveryFixture stands up an httptest server that serves both well-known
// docs (or a subset, depending on which fields are set) plus a tiny "MCP
// server" path that contributes nothing — only the origin matters.
type discoveryFixture struct {
	prm *protectedResourceMetadata
	as  *Endpoints
}

func (f *discoveryFixture) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-protected-resource":
			if f.prm == nil {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(f.prm)
		case "/.well-known/oauth-authorization-server", "/.well-known/openid-configuration":
			if f.as == nil {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(f.as)
		default:
			http.NotFound(w, r)
		}
	}
}

func TestDiscover_FullChain(t *testing.T) {
	as := httptest.NewServer((&discoveryFixture{as: &Endpoints{ //nolint:gosec // test fixture URLs, not credentials
		AuthorizationURL: "https://as.example/authorize",
		TokenURL:         "https://as.example/token",
	}}).handler())
	defer as.Close()

	mcp := httptest.NewServer((&discoveryFixture{prm: &protectedResourceMetadata{
		Resource:             "https://mcp.example/mcp",
		AuthorizationServers: []string{as.URL},
	}}).handler())
	defer mcp.Close()

	ep, err := Discover(context.Background(), mcp.URL+"/mcp")
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if ep.AuthorizationURL != "https://as.example/authorize" {
		t.Errorf("authz = %q", ep.AuthorizationURL)
	}
	if ep.TokenURL != "https://as.example/token" {
		t.Errorf("token = %q", ep.TokenURL)
	}
}

func TestDiscover_FallsBackToMcpOriginWhenNoPRM(t *testing.T) {
	mcp := httptest.NewServer((&discoveryFixture{as: &Endpoints{
		AuthorizationURL: "/authorize",
		TokenURL:         "/token",
	}}).handler())
	defer mcp.Close()

	ep, err := Discover(context.Background(), mcp.URL+"/mcp")
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if ep.AuthorizationURL != "/authorize" {
		t.Errorf("authz = %q", ep.AuthorizationURL)
	}
}

func TestDiscover_NothingAvailableReturnsError(t *testing.T) {
	mcp := httptest.NewServer((&discoveryFixture{}).handler())
	defer mcp.Close()

	_, err := Discover(context.Background(), mcp.URL+"/mcp")
	if err == nil {
		t.Fatal("expected error when neither well-known doc is available")
	}
}

func TestMergeEndpoints_OverrideWins(t *testing.T) {
	disc := &Endpoints{ //nolint:gosec // test fixture URLs, not credentials
		AuthorizationURL: "https://disc/auth",
		TokenURL:         "https://disc/token",
		Scopes:           []string{"a"},
	}
	out := MergeEndpoints(disc, &Endpoints{ //nolint:gosec // test fixture URLs, not credentials
		TokenURL: "https://override/token",
		Scopes:   []string{"x", "y"},
	})
	if out.AuthorizationURL != "https://disc/auth" {
		t.Errorf("AuthorizationURL = %q (discovery should remain)", out.AuthorizationURL)
	}
	if out.TokenURL != "https://override/token" {
		t.Errorf("TokenURL not overridden: %q", out.TokenURL)
	}
	if strings.Join(out.Scopes, ",") != "x,y" {
		t.Errorf("Scopes not overridden: %v", out.Scopes)
	}
}

func TestEndpoints_Validate(t *testing.T) {
	if err := (&Endpoints{AuthorizationURL: "a", TokenURL: "b"}).Validate(); err != nil {
		t.Errorf("valid endpoints rejected: %v", err)
	}
	if err := (&Endpoints{}).Validate(); err == nil {
		t.Error("empty endpoints should be invalid")
	}
	if err := (&Endpoints{AuthorizationURL: "a"}).Validate(); err == nil {
		t.Error("missing token url should be invalid")
	}
}
