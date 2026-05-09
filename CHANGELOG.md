# Changelog

All notable changes to this project are recorded here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches v1.0.0. Until then, minor version bumps may include breaking
changes (documented in their release notes).

## [Unreleased]

### Added

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
