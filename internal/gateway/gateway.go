// Package gateway connects to one or more MCP backends and federates their
// tools behind a single namespaced MCP server.
package gateway

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sebastienmelki/agentsmith/internal/config"
)

const namespaceSep = "__"

// Gateway federates one or more MCP backends behind a single Streamable HTTP
// endpoint, namespacing each backend's tools with "<target>__<tool>". Each
// backend connection uses its own HTTP transport that injects only that
// target's headers — secrets do not leak between backends.
type Gateway struct {
	backends []*backend
}

type backend struct {
	name    string
	url     string
	session *mcp.ClientSession
}

// New connects to all targets in cfg and returns a Gateway ready to serve.
func New(ctx context.Context, cfg *config.Config) (*Gateway, error) {
	g := &Gateway{}
	for _, t := range cfg.Targets {
		slog.Info("connecting to backend", "name", t.Name, "url", t.URL)
		client := mcp.NewClient(&mcp.Implementation{Name: "agentsmith", Version: "v0.0.1"}, nil)
		httpClient := &http.Client{
			Timeout:   60 * time.Second,
			Transport: &headerInjector{base: http.DefaultTransport, headers: t.Headers},
		}
		transport := &mcp.StreamableClientTransport{Endpoint: t.URL, HTTPClient: httpClient}

		connectCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		sess, err := client.Connect(connectCtx, transport, nil)
		cancel()
		if err != nil {
			g.Close()
			return nil, fmt.Errorf("connect %q (%s): %w", t.Name, t.URL, err)
		}
		g.backends = append(g.backends, &backend{name: t.Name, url: t.URL, session: sess})
	}
	return g, nil
}

// BuildServer returns a federated MCP Server that exposes a tool catalog
// aggregated across all connected backends. Tool names are prefixed with
// "<target>__" so collisions across backends are impossible. Each tool's
// handler forwards the call to the originating backend, preserving the raw
// JSON arguments.
func (g *Gateway) BuildServer(ctx context.Context) (*mcp.Server, error) {
	server := mcp.NewServer(&mcp.Implementation{Name: "agentsmith", Version: "v0.0.1"}, nil)
	totalTools := 0
	for _, b := range g.backends {
		listCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		result, err := b.session.ListTools(listCtx, nil)
		cancel()
		if err != nil {
			return nil, fmt.Errorf("list tools from %q: %w", b.name, err)
		}
		for _, t := range result.Tools {
			b := b
			original := t
			namespaced := *t
			namespaced.Name = b.name + namespaceSep + t.Name
			server.AddTool(&namespaced, makeToolHandler(b, original.Name))
		}
		slog.Info("registered tools from backend", "backend", b.name, "count", len(result.Tools))
		totalTools += len(result.Tools)
	}
	slog.Info("federation ready", "total_tools", totalTools, "backends", len(g.backends))
	return server, nil
}

func makeToolHandler(b *backend, originalName string) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		slog.Info("tool call", "backend", b.name, "tool", originalName)
		var args any
		if len(req.Params.Arguments) > 0 {
			args = req.Params.Arguments
		}
		return b.session.CallTool(ctx, &mcp.CallToolParams{
			Name:      originalName,
			Arguments: args,
			Meta:      req.Params.Meta,
		})
	}
}

// Close terminates all backend sessions.
func (g *Gateway) Close() {
	for _, b := range g.backends {
		if b.session != nil {
			_ = b.session.Close()
		}
	}
}

// SplitNamespacedTool reverses the namespacing applied at registration. Useful
// for downstream consumers that want to display the source backend separately
// from the tool name.
func SplitNamespacedTool(name string) (target, tool string, ok bool) {
	before, after, ok := strings.Cut(name, namespaceSep)
	if !ok {
		return "", name, false
	}
	return before, after, true
}

// headerInjector is a per-target RoundTripper that adds only that target's
// headers to outgoing requests. This is the core trick that lets agentsmith
// keep federation while scoping secrets per-backend — agentgateway 1.2's
// route-level header policy can't do this without leaking creds across targets.
type headerInjector struct {
	base    http.RoundTripper
	headers map[string]string
}

func (h *headerInjector) RoundTrip(req *http.Request) (*http.Response, error) {
	for k, v := range h.headers {
		req.Header.Set(k, v)
	}
	return h.base.RoundTrip(req)
}
