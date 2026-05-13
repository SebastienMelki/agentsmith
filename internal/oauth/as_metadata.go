package oauth

// BackendScope returns the OAuth scope string that represents a single
// upstream backend. Each configured OAuth backend is modelled as one scope so
// MCP clients can request exactly the backends they need at /oauth/authorize,
// and the gateway can issue insufficient_scope errors when a tool call
// touches a backend outside the granted set.
//
// Format: "<backend>:*". The wildcard suffix leaves room for fine-grained
// scopes later ("worldmonitor:read", "worldmonitor:write") without breaking
// existing tokens.
func BackendScope(backend string) string { return backend + ":*" }

// ProtectedResourceMetadata is the subset of RFC 9728 we serve at
// /.well-known/oauth-protected-resource. It points MCP clients at the
// gateway's own authorization server.
type ProtectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`
	ResourceName           string   `json:"resource_name,omitempty"`
}

// AuthorizationServerMetadata is the subset of RFC 8414 we serve at
// /.well-known/oauth-authorization-server. MCP clients read this to learn
// where to POST DCR, where to start /authorize, and where to swap codes for
// tokens.
type AuthorizationServerMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
}
