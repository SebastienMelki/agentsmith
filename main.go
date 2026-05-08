package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sebastienmelki/agentsmith/internal/config"
	"github.com/sebastienmelki/agentsmith/internal/gateway"
)

func main() {
	cfgPath := flag.String("f", "config.yaml", "path to config file")
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

	gw, err := gateway.New(ctx, cfg)
	if err != nil {
		return err
	}
	defer gw.Close()

	server, err := gw.BuildServer(ctx)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.Handle(cfg.Path, mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		return server
	}, nil))

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("agentsmith listening on %s%s", cfg.ListenAddr, cfg.Path)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	log.Println("agentsmith: shutting down")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	return srv.Shutdown(shutdownCtx)
}
