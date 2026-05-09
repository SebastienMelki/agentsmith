# agentsmith

**agentsmith** is a lightweight [Model Context Protocol (MCP)](https://modelcontextprotocol.io) federation gateway written in Go.

It connects to multiple MCP backend servers, aggregates their tools into a single Streamable HTTP endpoint, and namespaces them so there are no collisions — all while keeping each backend's credentials strictly isolated from the others.

## Why agentsmith?

Standard HTTP gateways (like agentgateway) operate at the transport layer and therefore can't scope secrets per-backend without leaking credentials across routes. agentsmith speaks MCP natively on both sides: each backend gets its own `http.Client` with a dedicated `RoundTripper` that injects only that backend's headers. A Slack token will never travel in a request to a Dodo Payments backend, and vice versa.

```
 MCP client (Claude, Cursor, …)
         │  Streamable HTTP /mcp
         ▼
   ┌─────────────┐
   │ agentsmith  │   federates tools, namespaces them <target>__<tool>
   └──────┬──────┘
          │
    ┌─────┴──────┐
    ▼            ▼
 dodo-mcp     slack-mcp      … any number of MCP backends
```

## Features

- **Federation** — aggregate tools from N backends behind one `/mcp` endpoint
- **Namespacing** — tools are exposed as `<backend>__<tool>` (e.g. `dodo__create_payment`, `slack__post_message`), preventing collisions
- **Per-backend secret scoping** — each backend connection uses its own `http.Client`; headers never leak across targets
- **Structured logging** — all events emitted via `log/slog` with key-value fields
- **Graceful shutdown** — SIGINT/SIGTERM drains in-flight requests before exiting
- **Safe config** — `${VAR}` interpolation in YAML; startup fails loudly if any secret is unset

## Requirements

- Go 1.21+
- [golangci-lint v2](https://golangci-lint.run) (for `make lint`)

## Getting started

```bash
# 1. Clone
git clone https://github.com/sebastienmelki/agentsmith.git
cd agentsmith

# 2. Configure secrets
cp agentsmith.env.example agentsmith.env
$EDITOR agentsmith.env   # fill in real values

# 3. Configure targets
cp config.example.yaml config.yaml
$EDITOR config.yaml      # adjust backend URLs and headers as needed

# 4. Build and run
make run
```

agentsmith will start on `http://localhost:3001/mcp` by default.

## Configuration

### `config.yaml`

| Field | Default | Description |
|---|---|---|
| `listenAddr` | `:3001` | TCP address to listen on |
| `path` | `/mcp` | HTTP path for the MCP endpoint |
| `targets[].name` | — | Unique backend identifier (used as the tool namespace) |
| `targets[].url` | — | MCP Streamable HTTP endpoint of the backend |
| `targets[].headers` | — | Headers injected into every request to this backend |

Secrets can be referenced as `${MY_VAR}` and resolved from the environment. agentsmith refuses to start if any referenced variable is unset.

### `agentsmith.env`

A plain `.env` file (gitignored) loaded automatically at startup. In production, inject environment variables directly — the file is optional.

## Tool namespacing

A backend named `dodo` with a tool named `create_payment` will be exposed as `dodo__create_payment`. The double-underscore separator (`__`) was chosen because it is unlikely to appear in real tool names.

Use `gateway.SplitNamespacedTool(name)` to split a namespaced name back into `(target, tool)` pairs programmatically.

## Development

```bash
make build   # compile
make test    # run tests
make lint    # run golangci-lint
make fmt     # auto-format
make clean   # remove build artefacts
make help    # list all targets
```

## Adding a new backend

1. Start (or point to) the new MCP server.
2. Add an entry to `config.yaml`:

```yaml
targets:
  - name: my_service
    url: http://127.0.0.1:9000/mcp
    headers:
      Authorization: Bearer ${MY_SERVICE_TOKEN}
```

3. Add `MY_SERVICE_TOKEN` to `agentsmith.env`.
4. Restart agentsmith — it discovers tools at startup.

## License

[MIT](LICENSE)
