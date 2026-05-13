// Package main is the agentsmith entry point.
package main

import (
	"context"
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// TODO(oauth-mcp): construct identity/secrets/oauth deps before passing in.
	gw, err := gateway.New(ctx, cfg, gateway.Deps{})
	if err != nil {
		return err
	}
	defer gw.Close()

	// MCP server — serves the federated tool catalog.
	mcpMux := http.NewServeMux()
	mcpMux.Handle(cfg.Path, mcp.NewStreamableHTTPHandler(func(_ *http.Request) *mcp.Server {
		return gw.Server()
	}, nil))
	mcpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mcpMux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Admin server — operational status and control-plane endpoints.
	// TODO(oauth-mcp): wire identity + oauth handler into Options.
	adminSrv := &http.Server{
		Addr:              cfg.AdminAddr,
		Handler:           admin.New(gw, admin.Options{AuthMode: cfg.AuthMode}).Handler(),
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
