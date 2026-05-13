# Changelog

All notable changes to this project are recorded here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches v1.0.0. Until then, minor version bumps may include breaking
changes (documented in their release notes).

## [Unreleased]

### Added

- **OAuth 2.1 authorization server** — agentsmith now speaks the MCP
  authorization spec (RFC 9728 + RFC 8414 + RFC 7591) to its MCP clients in
  addition to its upstream backends. When at least one OAuth backend is
  configured in `unprotected` mode, the gateway exposes
  `/.well-known/oauth-protected-resource`, `/.well-known/oauth-authorization-server`,
  `/oauth/register`, `/oauth/authorize`, and `/oauth/token` on the MCP port,
  and the `/mcp` endpoint returns `401 + WWW-Authenticate: Bearer
  resource_metadata="..."` to clients without a gateway-issued bearer. MCP
  clients that implement the spec (Claude Code, Cursor, …) **open the browser
  automatically** for the first connect — no more pasting connect URLs from
  tool-error messages. Each configured OAuth backend is exposed as the scope
  `<backend>:*`; `/oauth/authorize` chains the browser through every requested
  backend's upstream OAuth in turn before minting the final code, so a single
  consent dance covers however many backends the client asked for. Tokens
  are opaque, 24h TTL, and refreshable via the standard `refresh_token` grant.
- **Per-backend call metrics** — each backend now tracks total calls, total
  errors, summed latency, and a per-tool call count. All counters are
  in-memory with no external dependency; the data model is designed so a
  Prometheus exporter can be layered on later without structural changes.
- **Rolling call log** — a fixed-size ring buffer (500 entries) per backend
  records every tool invocation with its tool name, timestamp, duration,
  success/error status, and the full JSON-encoded request arguments and
  response body.
- **Aggregate metrics bar** on the dashboard — a one-line summary above the
  backends table showing gateway-wide totals: calls, errors, error rate, and
  average latency. Per-backend calls, errors, and avg-latency columns added
  to the table.
- **Per-backend metrics strip** on the detail page — the status article now
  includes call/error/latency stats beneath the connectivity chips.
- **Call Log dialog** on the detail page — a sticky "▶ Call Log" button
  (fixed bottom-right) opens a native `<dialog>` showing the 500-entry ring
  buffer. Each row is a collapsible `<details>` element with the full request
  and response JSON. The dialog lives outside the htmx-polled region so it
  survives background refreshes.
- **SSE live log tail** — `GET /ui/backends/{name}/logs/stream` is a
  Server-Sent Events endpoint that pushes each new `CallEntry` as a `log`
  event. The dialog connects lazily (on first open) and stays subscribed for
  the page lifetime; new rows are prepended in real time without polling.
  A 15-second heartbeat comment keeps the connection alive through proxies.
- **Per-user OAuth identities** with `authMode: protected` — each MCP caller
  authenticates with an API key and gets their own OAuth tokens per backend.
  Backends declare `auth.type: oauth` in `config.yaml`; the gateway runs
  RFC 9728 / RFC 8414 discovery and RFC 7591 Dynamic Client Registration
  on first connect, mints per-user signed connect tickets, and refreshes
  access tokens transparently.

### Changed

- **OAuth `OnSuccess` hook returns an error** and `HandleCallback` renders a
  partial-success page when post-OAuth tool registration fails. Tokens are
  still persisted; re-clicking the connect link reruns the hook.
- **`oauth.trustForwardedHeaders` opt-in** — the auto-derived OAuth
  `redirect_uri` no longer honours `X-Forwarded-Proto` / `X-Forwarded-Host`
  by default. Set the new flag (or, preferred, set `oauth.callbackBaseUrl`
  explicitly) when running behind a trusted proxy.
- **`make test` runs with `-race`** so the convenience target matches CI.
- **Config rejects unsupported `${...}` placeholders** — names that don't
  match `[A-Z_][A-Z0-9_]*` (e.g. lowercase) used to silently fall through
  expansion and surface much later as a confusing parse/auth error; the
  loader now flags them at startup with the offending name.
- **Operator-supplied ticket signing keys must be ≥ 32 characters** (was
  16). The ephemeral fallback (`randomHex(32)`) is unchanged.

### Fixed

- **Concurrent Dynamic Client Registration race** — two simultaneous
  `/oauth/connect` requests for the same DCR-required backend used to both
  hit the upstream `registration_endpoint` and torn-write the shared
  `*BackendConfig`. A per-backend `Registry.LockForUpdate` plus copy-on-write
  serializes updates and coalesces redundant DCR calls.
- **Unbounded `userSessions` map** in the gateway — a per-Gateway reaper
  goroutine now closes per-user OAuth sessions idle longer than 30 minutes
  on a 5-minute interval, so once-and-done users no longer leave entries
  behind for the lifetime of the process.
- **Unbounded `inflight` map** in `secrets.RefreshingTokenStore` — refresh
  locks are reference-counted and reclaimed when the last waiter releases.
- **SSE subscriber channels closed on shutdown** — `Gateway.Close()` now
  closes every `logSubs` channel under lock; admin SSE handlers exit cleanly
  via `entry, ok := <-ch` instead of blocking until the request context
  cancels.
- **`DELETE /users/{id}` refuses outside protected mode** to match the
  existing guard on `POST /users` (asymmetry, not a security hole — the
  admin port is documented as unauthenticated).
- **`publish.yml` only pushes when Docker Hub credentials are configured**
  so forks running the workflow without secrets do a build-only validation
  instead of failing at the push step. The header comment had always
  claimed this, but `push: true` was unconditional.
- **OAuth post-callback hook errors no longer log twice** — the handler is
  the single source of truth.

### Security

- **Documented that the admin port issues MCP credentials.** The previous
  README warned about read-only state exposure, but in `protected` mode
  `POST /users` mints API keys valid against the MCP endpoint. Reaching
  the admin port should be treated as full auth bypass; bind it to
  `127.0.0.1` or a sidecar-only network.

## [0.1.0] — 2026-05-09

Initial public release.

### Added

- MCP federation gateway: connect to N MCP backends and expose their tools
  behind a single Streamable HTTP `/mcp` endpoint.
- Per-backend credential isolation via dedicated `http.Client` + `headerInjector`
  `RoundTripper` per target — headers configured for one backend never appear
  in requests to another.
- Tool namespacing as `<backend>__<tool>` to prevent collisions across
  backends, with `gateway.SplitNamespacedTool` to reverse the mapping.
- YAML configuration with `${VAR}` interpolation; the gateway refuses to
  start if any referenced environment variable is unset.
- Optional `agentsmith.env` (gitignored) loaded at startup via `godotenv`.
- Non-blocking startup: backends connect in independent goroutines with
  exponential backoff (2 s → 2 min, ±10 % jitter) and reconnect loops, so the
  gateway stays available when individual upstreams are temporarily down.
- Admin HTTP server (separate port, default `:3002`):
  - `GET /healthz` liveness/readiness probe.
  - `GET /backends` JSON status array.
  - `GET /` templ + htmx dashboard with live backend cards and per-backend
    detail pages showing the full hydrated tool list.
- Structured logging via `log/slog` with snake_case keys.
- Graceful shutdown on SIGINT/SIGTERM, draining in-flight requests within 5 s.
- Two example configurations: `examples/dodo-and-slack/`,
  `examples/single-backend/`.

[Unreleased]: https://github.com/sebastienmelki/agentsmith/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/sebastienmelki/agentsmith/releases/tag/v0.1.0
