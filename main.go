// Package main is the agentsmith entry point.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sebastienmelki/agentsmith/internal/admin"
	"github.com/sebastienmelki/agentsmith/internal/config"
	"github.com/sebastienmelki/agentsmith/internal/gateway"
	"github.com/sebastienmelki/agentsmith/internal/identity"
	"github.com/sebastienmelki/agentsmith/internal/oauth"
	"github.com/sebastienmelki/agentsmith/internal/secrets"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	// Best-effort: load a local .env file if present. Production deployments
	// are expected to inject environment variables directly.
	if err := godotenv.Load("agentsmith.env"); err != nil && !os.IsNotExist(err) {
		slog.Warn("could not load agentsmith.env", "error", err)
	}

	cfgPath := flag.String("f", "config.yaml", "path to config file (copy from config.example.yaml)")
	flag.Parse()

	if err := run(*cfgPath); err != nil {
		fmt.Fprintf(os.Stderr, "agentsmith: %v\n", err)
		os.Exit(1)
	}
}

func run(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}

	if cfg.AuthMode == config.ModeUnprotected {
		slog.Warn("MCP endpoint is unauthenticated — any client reaching it can use connected OAuth identities. Set authMode: protected in config.yaml for per-user isolation.", "auth_mode", string(cfg.AuthMode))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Identity (per-user API keys) and secrets (per-(user, backend) OAuth tokens).
	idStore := identity.NewMemoryStore()
	memTokens := secrets.NewMemoryTokenStore()

	// OAuth registry, refresher, ticket signer, and handler. The registry is
	// populated below from per-target config (+ discovery). The signer is used
	// by the gateway to mint connect-URL tickets and verified by the handler
	// when the user lands at /oauth/connect.
	oauthReg := oauth.NewRegistry()
	tokens := secrets.NewRefreshingTokenStore(memTokens, oauth.NewRefresher(oauthReg))

	ticketKey := cfg.OAuth.TicketKey
	if ticketKey == "" {
		// Generate an ephemeral key so existing tickets become invalid on
		// restart. Set oauth.ticketKey in config to make tickets survive
		// restarts (e.g. when paired with persisted tokens later).
		ticketKey, err = randomHex(32)
		if err != nil {
			return fmt.Errorf("generate oauth ticket key: %w", err)
		}
		slog.Info("no oauth.ticketKey configured — using ephemeral key (connect URLs do not survive restart)")
	}
	signer, err := oauth.NewTicketSigner(ticketKey)
	if err != nil {
		return err
	}

	// Construct the gateway first so we can reference RegisterToolsForOAuthBackend
	// from the OAuth handler's OnSuccess hook.
	gw, err := gateway.New(ctx, cfg, gateway.Deps{
		Tokens:          tokens,
		Tickets:         signer,
		OAuthRegistry:   oauthReg,
		CallbackBaseURL: cfg.OAuth.CallbackBaseURL,
	})
	if err != nil {
		return err
	}
	defer gw.Close()

	// Resolve per-target OAuth config — explicit override wins over discovery.
	// Failures here do not abort startup; the backend stays in awaiting_auth
	// and operators can fix the config and restart.
	for _, t := range cfg.Targets {
		if t.Auth == nil || t.Auth.Type != config.AuthTypeOAuth {
			continue
		}
		if err := registerOAuthBackend(ctx, oauthReg, gw, t); err != nil {
			slog.Warn("oauth backend init failed — fix config and restart", "backend", t.Name, "error", err.Error())
		}
	}

	// Wire the OAuth handler now that the registry is populated.
	oauthHandler := oauth.New(oauth.HandlerDeps{
		Tickets:         signer,
		Tokens:          memTokens, // raw store: callback saves; refresher is read-side
		Registry:        oauthReg,
		CallbackBaseURL: cfg.OAuth.CallbackBaseURL,
		OnSuccess: func(ctx context.Context, backend, userID string) {
			if err := gw.RegisterToolsForOAuthBackend(ctx, backend, userID); err != nil {
				slog.Warn("post-OAuth tool registration failed", "backend", backend, "user_id", userID, "error", err.Error())
			}
		},
	})

	// MCP server — serves the federated tool catalog, wrapped with the
	// identity middleware so tool handlers can attribute calls to a user.
	mcpMux := http.NewServeMux()
	mcpMux.Handle(cfg.Path, mcp.NewStreamableHTTPHandler(func(_ *http.Request) *mcp.Server {
		return gw.Server()
	}, nil))
	mcpHandler := identity.Middleware(cfg.AuthMode, idStore)(mcpMux)
	mcpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mcpHandler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Admin server — operational status, user management, OAuth flow.
	adminSrv := &http.Server{
		Addr: cfg.AdminAddr,
		Handler: admin.New(gw, admin.Options{
			Users:        idStore,
			OAuthHandler: oauthHandler,
			AuthMode:     cfg.AuthMode,
		}).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// serverErr carries the first fatal error from either server so we can
	// surface it after a clean shutdown.
	serverErr := make(chan error, 2)

	go func() {
		slog.Info("MCP server listening", "addr", cfg.ListenAddr, "path", cfg.Path)
		if err := mcpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- fmt.Errorf("MCP server: %w", err)
		}
	}()

	go func() {
		slog.Info("admin server listening", "addr", cfg.AdminAddr)
		if err := adminSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- fmt.Errorf("admin server: %w", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	var runErr error
	select {
	case <-sig:
		slog.Info("shutting down")
	case runErr = <-serverErr:
		slog.Error("server error, shutting down", "error", runErr)
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = mcpSrv.Shutdown(shutdownCtx)
	_ = adminSrv.Shutdown(shutdownCtx)
	return runErr
}

// registerOAuthBackend resolves the OAuth client config for one target by
// merging an MCP-spec discovery response with config overrides, validates it,
// and stashes it on the registry.
func registerOAuthBackend(ctx context.Context, reg *oauth.Registry, gw *gateway.Gateway, t config.Target) error {
	override := &oauth.Endpoints{
		AuthorizationURL: t.Auth.AuthorizationURL,
		TokenURL:         t.Auth.TokenURL,
	}
	discovered, derr := oauth.Discover(ctx, t.URL)
	if derr != nil {
		slog.Info("OAuth discovery skipped — using config overrides", "backend", t.Name, "reason", derr.Error())
	}
	ep := oauth.MergeEndpoints(discovered, override)
	if err := ep.Validate(); err != nil {
		return err
	}
	cfg := &oauth.BackendConfig{
		Name:         t.Name,
		ClientID:     t.Auth.ClientID,
		ClientSecret: t.Auth.ClientSecret,
		Scopes:       t.Auth.Scopes,
		Endpoints:    ep,
	}
	reg.Set(cfg)
	gw.SetOAuthConfig(t.Name, cfg)
	return nil
}

// randomHex returns 2*n hex characters of cryptographically-random bytes.
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
