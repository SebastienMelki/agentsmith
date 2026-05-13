package oauth

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// AS endpoint paths. The gateway mounts these on the MCP server so they share
// the same origin as the MCP endpoint that issues 401 challenges referencing
// them — RFC 9728 metadata URLs must resolve from the resource's own origin.
const (
	ProtectedResourcePath    = "/.well-known/oauth-protected-resource"
	AuthorizationServerPath  = "/.well-known/oauth-authorization-server"
	RegisterPath             = "/oauth/register"
	AuthorizePath            = "/oauth/authorize"
	TokenPath                = "/oauth/token" //nolint:gosec // G101: this is a URL path, not a credential
	authorizationCodeTTL     = 10 * time.Minute
)

// HandleProtectedResource serves RFC 9728 metadata. MCP clients fetch this
// after receiving a 401 + WWW-Authenticate from /mcp and use it to discover
// the authorization server they should drive.
func (h *Handler) HandleProtectedResource(w http.ResponseWriter, r *http.Request) {
	base := h.baseURL(r)
	scopes := make([]string, 0, len(h.deps.OAuthBackends))
	for _, name := range h.deps.OAuthBackends {
		scopes = append(scopes, BackendScope(name))
	}
	doc := ProtectedResourceMetadata{
		Resource:               base + "/mcp",
		AuthorizationServers:   []string{base},
		ScopesSupported:        scopes,
		BearerMethodsSupported: []string{"header"},
		ResourceName:           "agentsmith",
	}
	writeJSON(w, http.StatusOK, doc)
}

// HandleAuthorizationServer serves RFC 8414 metadata at the gateway's own
// well-known path so MCP clients can run OAuth 2.1 against us.
func (h *Handler) HandleAuthorizationServer(w http.ResponseWriter, r *http.Request) {
	base := h.baseURL(r)
	scopes := make([]string, 0, len(h.deps.OAuthBackends))
	for _, name := range h.deps.OAuthBackends {
		scopes = append(scopes, BackendScope(name))
	}
	doc := AuthorizationServerMetadata{
		Issuer:                            base,
		AuthorizationEndpoint:             base + AuthorizePath,
		TokenEndpoint:                     base + TokenPath,
		RegistrationEndpoint:              base + RegisterPath,
		ScopesSupported:                   scopes,
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
		TokenEndpointAuthMethodsSupported: []string{"none"},
		CodeChallengeMethodsSupported:     []string{"S256"},
	}
	writeJSON(w, http.StatusOK, doc)
}

// HandleRegister implements a minimal RFC 7591 Dynamic Client Registration
// endpoint. MCP clients POST { "client_name": ..., "redirect_uris": [...] }
// and we return a fresh client_id. We do not issue client secrets — all MCP
// clients we expect are public (PKCE-only).
func (h *Handler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if h.deps.Clients == nil {
		writeOAuthError(w, http.StatusServiceUnavailable, "server_error", "client registration not configured")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "read body: "+err.Error())
		return
	}
	var req struct {
		ClientName              string   `json:"client_name"`
		RedirectURIs            []string `json:"redirect_uris"`
		GrantTypes              []string `json:"grant_types"`
		ResponseTypes           []string `json:"response_types"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "parse: "+err.Error())
		return
	}
	if len(req.RedirectURIs) == 0 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "redirect_uris is required")
		return
	}
	for _, u := range req.RedirectURIs {
		if _, err := url.Parse(u); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uri parse: "+err.Error())
			return
		}
	}
	client, err := h.deps.Clients.Register(req.ClientName, req.RedirectURIs)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", err.Error())
		return
	}
	slog.Info("dcr: registered MCP client",
		"client_id_prefix", clientIDPrefix(client.ID),
		"client_name", req.ClientName,
		"redirect_uris", len(req.RedirectURIs),
	)
	resp := map[string]any{
		"client_id":                  client.ID,
		"client_id_issued_at":        client.IssuedAt.Unix(),
		"client_name":                client.Name,
		"redirect_uris":              client.RedirectURIs,
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	}
	writeJSON(w, http.StatusCreated, resp)
}

// HandleAuthorize starts a multi-backend authorization. The client browser
// arrives via /oauth/authorize?response_type=code&client_id=...&redirect_uri=...&scope=...&state=...&code_challenge=...&code_challenge_method=S256
//
// For each scope that maps to a backend whose upstream tokens are missing
// for the current user, we redirect the browser through that backend's own
// OAuth in turn. When all requested backends are linked, we mint an
// authorization code and 302 the browser back to the MCP client's redirect_uri.
func (h *Handler) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	if h.deps.Clients == nil || h.deps.Sessions == nil || h.deps.Codes == nil {
		writeOAuthError(w, http.StatusServiceUnavailable, "server_error", "authorization server not configured")
		return
	}
	q := r.URL.Query()

	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	if clientID == "" || redirectURI == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "client_id and redirect_uri are required")
		return
	}
	client, err := h.deps.Clients.Lookup(clientID)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client", err.Error())
		return
	}
	if !client.AllowsRedirect(redirectURI) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri not registered for this client")
		return
	}
	// From here on, errors are reported back to the client via redirect — the
	// browser is committed and a JSON body wouldn't be useful.
	clientState := q.Get("state")
	respType := q.Get("response_type")
	if respType != "code" {
		redirectWithError(w, r, redirectURI, clientState, "unsupported_response_type", "only response_type=code is supported")
		return
	}
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")
	if codeChallenge == "" || codeChallengeMethod != "S256" {
		redirectWithError(w, r, redirectURI, clientState, "invalid_request", "code_challenge with method=S256 is required")
		return
	}

	if h.deps.IdentityResolver == nil {
		redirectWithError(w, r, redirectURI, clientState, "server_error", "identity resolver not configured")
		return
	}
	userID, ok := h.deps.IdentityResolver(r)
	if !ok {
		redirectWithError(w, r, redirectURI, clientState, "access_denied", "no authenticated user — log in first")
		return
	}

	// Parse requested scopes. Default to "all configured OAuth backends" so
	// MCP clients that don't know our backend names get a sensible behaviour.
	requested := parseScopes(q.Get("scope"))
	if len(requested) == 0 {
		for _, name := range h.deps.OAuthBackends {
			requested = append(requested, BackendScope(name))
		}
	}
	if len(requested) == 0 {
		// No OAuth backends configured — mint an empty-scope token immediately.
		// Useful for static-only deployments that still want the protocol.
		h.completeAuthz(w, r, &authzSession{
			ClientID:            clientID,
			ClientRedirectURI:   redirectURI,
			ClientState:         clientState,
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: codeChallengeMethod,
			ResourceIndicator:   q.Get("resource"),
			UserID:              userID,
			Scopes:              nil,
			Granted:             nil,
		})
		return
	}

	// Validate every requested scope maps to a known OAuth backend.
	pending := make([]string, 0, len(requested))
	granted := make([]string, 0, len(requested))
	for _, s := range requested {
		backend, ok := backendFromScope(s)
		if !ok || !h.knowsBackend(backend) {
			redirectWithError(w, r, redirectURI, clientState, "invalid_scope", "unknown scope: "+s)
			return
		}
		// Skip backends whose tokens are already on file for this user — they
		// don't need a fresh round trip and shouldn't re-prompt the user.
		if h.userHasTokens(userID, backend) {
			granted = append(granted, s)
			continue
		}
		pending = append(pending, s)
	}

	sess := &authzSession{
		ClientID:            clientID,
		ClientRedirectURI:   redirectURI,
		ClientState:         clientState,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		ResourceIndicator:   q.Get("resource"),
		UserID:              userID,
		Scopes:              requested,
		Pending:             pending,
		Granted:             granted,
	}
	if _, err := h.deps.Sessions.create(sess); err != nil {
		redirectWithError(w, r, redirectURI, clientState, "server_error", "session create: "+err.Error())
		return
	}
	slog.Info("oauth: authorize request",
		"client_id_prefix", clientIDPrefix(clientID),
		"user_id", userID,
		"requested_scopes", len(requested),
		"already_granted", len(granted),
		"pending", len(pending),
	)

	if len(pending) == 0 {
		h.completeAuthz(w, r, sess)
		return
	}

	h.redirectToNextBackend(w, r, sess)
}

// redirectToNextBackend picks the head of sess.Pending and 302s the browser
// through that backend's upstream OAuth. The stateEntry it stashes carries
// sess.ID so the callback handler can find this session and continue the chain.
func (h *Handler) redirectToNextBackend(w http.ResponseWriter, r *http.Request, sess *authzSession) {
	if len(sess.Pending) == 0 {
		h.completeAuthz(w, r, sess)
		return
	}
	scope := sess.Pending[0]
	backend, ok := backendFromScope(scope)
	if !ok {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "malformed pending scope: "+scope)
		return
	}
	authURL, _, err := h.beginUpstreamFlow(r, backend, sess.UserID, sess.ID)
	if err != nil {
		redirectWithError(w, r, sess.ClientRedirectURI, sess.ClientState, "server_error", err.Error())
		return
	}
	// authURL is built from a registered backend config + gateway-minted state.
	http.Redirect(w, r, authURL, http.StatusFound) //nolint:gosec // G710: gateway-controlled URL
}

// advanceAuthzSession is called from HandleCallback once upstream tokens are
// persisted. It moves the just-completed scope from Pending to Granted and
// either redirects to the next backend or mints the final authorization code.
func (h *Handler) advanceAuthzSession(w http.ResponseWriter, r *http.Request, sessID, backend string) {
	if h.deps.Sessions == nil {
		writeCallbackError(w, "authorization session store not configured")
		return
	}
	sess := h.deps.Sessions.markGranted(sessID, BackendScope(backend))
	if sess == nil {
		writeCallbackError(w, "authorization session expired or unknown — restart the flow")
		return
	}
	if len(sess.Pending) > 0 {
		h.redirectToNextBackend(w, r, sess)
		return
	}
	h.completeAuthz(w, r, sess)
}

// completeAuthz mints an authorization code bound to the session and redirects
// the browser back to the MCP client's redirect_uri. After this point the
// session is finished — we remove it from the store so its memory is freed.
func (h *Handler) completeAuthz(w http.ResponseWriter, r *http.Request, sess *authzSession) {
	code, err := randURLSafe(32)
	if err != nil {
		redirectWithError(w, r, sess.ClientRedirectURI, sess.ClientState, "server_error", "code: "+err.Error())
		return
	}
	h.deps.Codes.put(&authorizationCode{
		Code:                code,
		ClientID:            sess.ClientID,
		UserID:              sess.UserID,
		RedirectURI:         sess.ClientRedirectURI,
		Scopes:              append(sess.Granted, sess.Pending...),
		CodeChallenge:       sess.CodeChallenge,
		CodeChallengeMethod: sess.CodeChallengeMethod,
		Expires:             time.Now().Add(authorizationCodeTTL),
	})
	if sess.ID != "" {
		h.deps.Sessions.remove(sess.ID)
	}
	u, err := url.Parse(sess.ClientRedirectURI)
	if err != nil {
		writeCallbackError(w, "invalid client redirect_uri: "+err.Error())
		return
	}
	q := u.Query()
	q.Set("code", code)
	if sess.ClientState != "" {
		q.Set("state", sess.ClientState)
	}
	u.RawQuery = q.Encode()
	slog.Info("oauth: authorization complete — redirecting back to client",
		"client_id_prefix", clientIDPrefix(sess.ClientID),
		"user_id", sess.UserID,
		"scopes", len(sess.Granted)+len(sess.Pending),
	)
	// u was built from sess.ClientRedirectURI, which was validated against
	// the registered client's redirect_uris at /oauth/authorize entry.
	http.Redirect(w, r, u.String(), http.StatusFound) //nolint:gosec // G710: redirect_uri validated at session start
}

// HandleToken implements /oauth/token for both the authorization_code and
// refresh_token grants. RFC 6749 §5.2 says errors are JSON 400s with an
// error code; we follow that to the letter so MCP clients can pattern-match.
func (h *Handler) HandleToken(w http.ResponseWriter, r *http.Request) {
	if h.deps.Codes == nil || h.deps.IssuedTokens == nil {
		writeOAuthError(w, http.StatusServiceUnavailable, "server_error", "token endpoint not configured")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "parse form: "+err.Error())
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		h.handleTokenAuthorizationCode(w, r)
	case "refresh_token":
		h.handleTokenRefresh(w, r)
	default:
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type must be authorization_code or refresh_token")
	}
}

func (h *Handler) handleTokenAuthorizationCode(w http.ResponseWriter, r *http.Request) {
	code := r.PostForm.Get("code")
	clientID := r.PostForm.Get("client_id")
	redirectURI := r.PostForm.Get("redirect_uri")
	codeVerifier := r.PostForm.Get("code_verifier")
	if code == "" || clientID == "" || redirectURI == "" || codeVerifier == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code, client_id, redirect_uri and code_verifier are required")
		return
	}
	ac := h.deps.Codes.take(code)
	if ac == nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "code expired or already redeemed")
		return
	}
	if ac.ClientID != clientID || ac.RedirectURI != redirectURI {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "code does not match client_id/redirect_uri")
		return
	}
	if err := VerifyPKCE(codeVerifier, ac.CodeChallenge, ac.CodeChallengeMethod); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", err.Error())
		return
	}
	tok, err := h.deps.IssuedTokens.Issue(ac.ClientID, ac.UserID, ac.Scopes)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "issue token: "+err.Error())
		return
	}
	slog.Info("oauth: issued token",
		"client_id_prefix", clientIDPrefix(ac.ClientID),
		"user_id", ac.UserID,
		"scopes", len(ac.Scopes),
	)
	writeTokenResponse(w, tok)
}

func (h *Handler) handleTokenRefresh(w http.ResponseWriter, r *http.Request) {
	rt := r.PostForm.Get("refresh_token")
	if rt == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}
	tok, err := h.deps.IssuedTokens.Rotate(rt)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", err.Error())
		return
	}
	writeTokenResponse(w, tok)
}

// userHasTokens reports whether the upstream secrets store already has a
// usable token pair for (userID, backend). When true, /oauth/authorize can
// skip that backend's OAuth round trip and immediately mark its scope granted.
func (h *Handler) userHasTokens(userID, backend string) bool {
	if h.deps.Tokens == nil {
		return false
	}
	_, err := h.deps.Tokens.Get(userID, backend)
	return err == nil
}

// knowsBackend reports whether name is one of the configured OAuth backends.
func (h *Handler) knowsBackend(name string) bool {
	return slices.Contains(h.deps.OAuthBackends, name)
}

// baseURL returns the gateway's scheme://host derived from r, honouring the
// operator-supplied CallbackBaseURL when set. Distinct from callbackURL which
// returns the full /oauth/callback/{backend} URL.
func (h *Handler) baseURL(r *http.Request) string {
	if h.deps.CallbackBaseURL != "" {
		return strings.TrimRight(h.deps.CallbackBaseURL, "/")
	}
	return deriveBaseURL(r, h.deps.TrustForwardedHeaders)
}

// backendFromScope splits "<backend>:*" into "<backend>". Returns false when
// the scope is malformed.
func backendFromScope(scope string) (string, bool) {
	before, after, ok := strings.Cut(scope, ":")
	if !ok || after != "*" {
		return "", false
	}
	return before, before != ""
}

// parseScopes turns a space-separated scope string into a deduplicated slice
// preserving input order. RFC 6749 says scopes are space-delimited.
func parseScopes(s string) []string {
	if s == "" {
		return nil
	}
	fields := strings.Fields(s)
	seen := make(map[string]struct{}, len(fields))
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if _, dup := seen[f]; dup {
			continue
		}
		seen[f] = struct{}{}
		out = append(out, f)
	}
	return out
}

// writeJSON marshals v as JSON to w with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeOAuthError emits an RFC 6749 §5.2 error response.
func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{
		"error":             code,
		"error_description": description,
	})
}

// redirectWithError sends the browser back to the MCP client with an OAuth
// error attached to the redirect_uri. Per RFC 6749 §4.1.2.1, errors after a
// validated redirect_uri travel via the redirect, not the response body.
func redirectWithError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, description string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		writeCallbackError(w, "invalid redirect_uri: "+err.Error())
		return
	}
	q := u.Query()
	q.Set("error", code)
	if description != "" {
		q.Set("error_description", description)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	// redirectURI is the caller-validated value from /oauth/authorize — we
	// only ever reach this point after AllowsRedirect or via callback paths
	// that derive from the same registry, so the host is safe.
	http.Redirect(w, r, u.String(), http.StatusFound) //nolint:gosec // G710: redirect_uri pre-validated
}

// writeTokenResponse formats a gateway-issued token pair per RFC 6749 §5.1.
func writeTokenResponse(w http.ResponseWriter, t *IssuedToken) {
	resp := map[string]any{
		"access_token":  t.AccessToken,
		"token_type":    "Bearer",
		"expires_in":    int64(time.Until(t.Expires).Seconds()),
		"refresh_token": t.RefreshToken,
	}
	if len(t.Scopes) > 0 {
		resp["scope"] = strings.Join(t.Scopes, " ")
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, resp)
}

// HandleASMount returns an http.Handler that serves all AS endpoints. Mount
// it on the MCP server's mux so the well-known docs resolve from the same
// origin the MCP endpoint advertises in WWW-Authenticate.
func (h *Handler) HandleASMount() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+ProtectedResourcePath, h.HandleProtectedResource)
	mux.HandleFunc("GET "+AuthorizationServerPath, h.HandleAuthorizationServer)
	mux.HandleFunc("POST "+RegisterPath, h.HandleRegister)
	mux.HandleFunc("GET "+AuthorizePath, h.HandleAuthorize)
	mux.HandleFunc("POST "+TokenPath, h.HandleToken)
	mux.HandleFunc("GET "+CallbackPath+"{backend}", h.HandleCallback)
	return mux
}

// FixedUserIdentity returns an IdentityResolver that always returns the same
// user ID. Used in unprotected mode where the gateway has a single synthetic
// caller.
func FixedUserIdentity(userID string) func(*http.Request) (string, bool) {
	return func(*http.Request) (string, bool) { return userID, userID != "" }
}

// LookupBearerToken returns the (userID, scopes) attached to the named bearer
// token by /oauth/token, or false if the token is unknown or expired. The MCP
// auth middleware uses this to convert "Authorization: Bearer <gateway>" into
// a *identity.User on the request context.
func (h *Handler) LookupBearerToken(token string) (userID string, scopes []string, ok bool) {
	if h.deps.IssuedTokens == nil {
		return "", nil, false
	}
	t, err := h.deps.IssuedTokens.Lookup(token)
	if err != nil {
		if errors.Is(err, ErrTokenExpired) {
			slog.Debug("oauth: bearer token expired", "token_prefix", clientIDPrefix(token))
		}
		return "", nil, false
	}
	return t.UserID, t.Scopes, true
}

// ResourceMetadataURL returns the absolute URL of the protected-resource
// metadata document, derived from the same base URL the AS uses. Suitable for
// embedding in WWW-Authenticate: resource_metadata="...".
func (h *Handler) ResourceMetadataURL(r *http.Request) string {
	return h.baseURL(r) + ProtectedResourcePath
}

