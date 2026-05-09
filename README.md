# agentsmith

[![CI](https://github.com/sebastienmelki/agentsmith/actions/workflows/ci.yml/badge.svg)](https://github.com/sebastienmelki/agentsmith/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/sebastienmelki/agentsmith.svg)](https://pkg.go.dev/github.com/sebastienmelki/agentsmith)
[![Go Report Card](https://goreportcard.com/badge/github.com/sebastienmelki/agentsmith)](https://goreportcard.com/report/github.com/sebastienmelki/agentsmith)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

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

- Go 1.25+
- [golangci-lint v2](https://golangci-lint.run) (for `make lint`)

## Getting started

```bash
# 1. Clone
git clone https://github.com/sebastienmelki/agentsmith.git
cd agentsmith

# 2. Pick an example that matches your setup and copy it
cp examples/dodo-and-slack/config.yaml config.yaml
$EDITOR config.yaml        # adjust backend URLs if needed

# 3. Add your backend credentials
cp examples/dodo-and-slack/.env.example agentsmith.env
$EDITOR agentsmith.env     # fill in real API keys/tokens

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

### `agentsmith.env` (gitignored)

A plain `.env` file loaded automatically at startup if present. It should contain the credentials for your specific backends — the variable names are whatever you reference via `${VAR}` in `config.yaml`. In production, inject environment variables directly; the file is entirely optional.

See `examples/` for deployment-specific `.env.example` files.

## Admin server

agentsmith ships a small operational HTTP server on a separate port (default `:3002`, configured via `adminAddr`):

| Path | Purpose |
|---|---|
| `GET /` | Live HTML dashboard — backend table with per-backend call counts, error rates, avg latency, and a gateway-wide aggregate bar; auto-refreshes every 5 s via htmx |
| `GET /ui/backends/{name}` | Per-backend detail page: connectivity state, metrics strip (calls / errors / avg latency), full tool list with schemas, and a **Call Log** button |
| `GET /ui/backends/{name}/logs/stream` | Server-Sent Events stream — pushes each `CallEntry` as a `log` event in real time; used by the dialog's live tail |
| `GET /healthz` | Liveness/readiness probe — `200` when at least one backend is connected, `503` otherwise |
| `GET /backends` | Per-backend status as a JSON array, suitable for scripts and monitoring agents |

### Call log

Every tool invocation is appended to a per-backend ring buffer (last 500 calls). Each entry contains the tool name, timestamp, duration, success/error flag, and the full JSON request and response objects. The buffer is purely in-memory — it resets on restart.

On any backend detail page, click the **▶ Call Log** button (fixed bottom-right) to open the log in a modal dialog. The dialog connects to the SSE stream on first open and prepends new entries live. Clicking the backdrop or the ✕ button closes it; the SSE connection stays alive in the background so no entries are missed.

> **Keep the admin port off public networks.** It exposes internal state and full request/response payloads with no authentication. Bind it to `127.0.0.1`, a private interface, or a sidecar-only network.

## Deployment

agentsmith ships with a hardened multi-stage `Dockerfile` (distroless/static base, stripped static binary, runs as non-root UID 65532). The final image is ~17–20 MB.

### Docker

Pre-built multi-arch images (amd64 + arm64) are published to Docker Hub:

```bash
docker pull sebastienmelki/agentsmith:latest

docker run --rm \
  -p 3001:3001 -p 3002:3002 \
  -v "$PWD/config.yaml:/etc/agentsmith/config.yaml:ro" \
  --env-file agentsmith.env \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  sebastienmelki/agentsmith:latest
```

Available tags: `latest` (last released `vX.Y.Z`), `X.Y.Z` / `X.Y` / `X` (semver), `edge` (latest `main`), and `sha-<short>` for traceability. To build locally instead: `docker build -t agentsmith:local .`

### Docker Compose

```bash
cp examples/dodo-and-slack/config.yaml config.yaml
cp examples/dodo-and-slack/.env.example agentsmith.env
$EDITOR agentsmith.env
docker compose up --build
```

`docker-compose.yaml` runs the container read-only, with all capabilities dropped and `no-new-privileges`.

### Railway / Fly.io / Render

Any platform that builds from a `Dockerfile` works out of the box:

1. **Fork** this repo (or push your own clone).
2. Copy an example to `config.yaml` and **commit it** — the root `config.yaml` is gitignored, so use `git add -f config.yaml`.
3. Connect the repo to your platform; it will detect the `Dockerfile` and build automatically.
4. Set each `${VAR}` referenced by your `config.yaml` as an environment variable / secret in the platform UI (e.g. `DODO_PAYMENTS_API_KEY`, `SLACK_TOKEN`). agentsmith refuses to start if any are unset.
5. **Bind to the platform's port.** Railway, Fly.io, and Render inject `$PORT` and route a single public port to the service. Update `config.yaml`:

   ```yaml
   listenAddr: ":${PORT}"
   ```

   The admin server still listens on `:3002` inside the container; on single-port PaaS it's reachable only from inside the network (which is what you want).

### AWS / VPS / Kubernetes

Push the image to your registry of choice (ECR, GHCR, Docker Hub) and run it like any other container:

```bash
docker tag agentsmith:latest <registry>/agentsmith:<tag>
docker push <registry>/agentsmith:<tag>
```

Liveness/readiness probes should target `GET /healthz` on the admin port (`:3002`).

## Non-goals

agentsmith is intentionally a small federation primitive, not a full API gateway. The following are **not** planned and are likely to be declined as feature requests:

- Authentication or authorization for incoming MCP clients (run agentsmith behind a service that handles this).
- Rate limiting, quota tracking, or per-user scoping.
- Vendor-specific MCP extensions or transports beyond Streamable HTTP.
- A persistent store — agentsmith is stateless across restarts by design.

If your use case needs any of the above, a layer in front of agentsmith (or an MCP server with broader scope) is the right place for it.

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

3. Add `MY_SERVICE_TOKEN=<value>` to `agentsmith.env`.
4. Restart agentsmith — it discovers tools at startup.

## Examples

The `examples/` directory contains ready-to-use configurations for common backend combinations:

| Example | Backends |
|---|---|
| [`dodo-and-slack/`](examples/dodo-and-slack/) | Dodo Payments + Slack |
| [`single-backend/`](examples/single-backend/) | Generic single-backend template |

## Contributing

PRs are welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for setup, conventions, and what's in/out of scope. Security issues: see [`SECURITY.md`](SECURITY.md).

## License

[MIT](LICENSE)
