// Package oauth implements the gateway side of the MCP authorization spec:
// well-known discovery against the upstream, PKCE authorization-code flow,
// refresh, signed connect-tickets, and the HTTP handlers that drive the
// browser-side flow.
package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Endpoints is the subset of the OAuth Authorization Server Metadata document
// (RFC 8414) and Protected Resource Metadata (RFC 9728) that the gateway
// needs to drive an authorization-code flow.
type Endpoints struct {
	AuthorizationURL string   `json:"authorization_endpoint"`
	TokenURL         string   `json:"token_endpoint"`
	RegistrationURL  string   `json:"registration_endpoint,omitempty"`
	Issuer           string   `json:"issuer,omitempty"`
	Scopes           []string `json:"scopes_supported,omitempty"`
}

// discoveryClient is the HTTP client used by Discover. Overridden in tests.
var discoveryClient = &http.Client{Timeout: 10 * time.Second}

// Discover walks the MCP authorization spec discovery chain starting from an
// MCP server URL:
//
//  1. GET <mcp-origin>/.well-known/oauth-protected-resource (RFC 9728)
//  2. Pick the first listed authorization_server (or fall back to that origin
//     if the document is missing)
//  3. GET <as-origin>/.well-known/oauth-authorization-server (RFC 8414)
//
// Missing documents are tolerated: the caller can supply explicit endpoints
// via config to fill in any gaps. Returns whatever was discovered plus a
// non-nil error only on transport failure or malformed JSON.
func Discover(ctx context.Context, mcpURL string) (*Endpoints, error) {
	mcpOrigin, err := originOf(mcpURL)
	if err != nil {
		return nil, fmt.Errorf("oauth: discover: parse mcp url: %w", err)
	}
	asOrigin := mcpOrigin
	if prm, prErr := fetchProtectedResource(ctx, mcpOrigin); prErr == nil && len(prm.AuthorizationServers) > 0 {
		asOrigin = prm.AuthorizationServers[0]
	}
	asm, err := fetchAuthorizationServer(ctx, asOrigin)
	if err != nil {
		return nil, err
	}
	return asm, nil
}

// protectedResourceMetadata is the subset of the RFC 9728 document we read.
type protectedResourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
}

func fetchProtectedResource(ctx context.Context, origin string) (*protectedResourceMetadata, error) {
	body, err := fetchWellKnown(ctx, origin+"/.well-known/oauth-protected-resource")
	if err != nil {
		return nil, err
	}
	var doc protectedResourceMetadata
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("oauth: parse protected-resource metadata: %w", err)
	}
	return &doc, nil
}

func fetchAuthorizationServer(ctx context.Context, origin string) (*Endpoints, error) {
	// Some servers expose authorization_endpoint as openid-configuration
	// instead. Try the OAuth-specific path first; fall back to OIDC.
	candidates := []string{
		origin + "/.well-known/oauth-authorization-server",
		origin + "/.well-known/openid-configuration",
	}
	var lastErr error
	for _, u := range candidates {
		body, err := fetchWellKnown(ctx, u)
		if err != nil {
			lastErr = err
			continue
		}
		var ep Endpoints
		if err := json.Unmarshal(body, &ep); err != nil {
			lastErr = fmt.Errorf("oauth: parse authorization-server metadata at %s: %w", u, err)
			continue
		}
		return &ep, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errors.New("oauth: no authorization-server metadata found")
}

func fetchWellKnown(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := discoveryClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauth: fetch %s: %w", u, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oauth: fetch %s: status %d", u, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// originOf returns scheme://host of a URL, trimming any path/query/fragment.
func originOf(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("oauth: url has no scheme/host: %q", raw)
	}
	return u.Scheme + "://" + u.Host, nil
}

// MergeEndpoints overlays explicit values onto a discovered set. Explicit
// values from config win over discovery so operators can fix non-conformant
// servers without abandoning auto-discovery for the others.
func MergeEndpoints(discovered, override *Endpoints) *Endpoints {
	out := &Endpoints{}
	if discovered != nil {
		*out = *discovered
	}
	if override == nil {
		return out
	}
	if override.AuthorizationURL != "" {
		out.AuthorizationURL = override.AuthorizationURL
	}
	if override.TokenURL != "" {
		out.TokenURL = override.TokenURL
	}
	if override.RegistrationURL != "" {
		out.RegistrationURL = override.RegistrationURL
	}
	if override.Issuer != "" {
		out.Issuer = override.Issuer
	}
	if len(override.Scopes) > 0 {
		out.Scopes = override.Scopes
	}
	return out
}

// Validate reports whether the endpoints are usable for an authorization-code
// flow. A useful Endpoints must at least carry both URLs.
func (e *Endpoints) Validate() error {
	if e == nil {
		return errors.New("oauth: nil endpoints")
	}
	var missing []string
	if e.AuthorizationURL == "" {
		missing = append(missing, "authorization_endpoint")
	}
	if e.TokenURL == "" {
		missing = append(missing, "token_endpoint")
	}
	if len(missing) > 0 {
		return fmt.Errorf("oauth: endpoints missing %s — supply via config override", strings.Join(missing, ", "))
	}
	return nil
}
