# Changelog

All notable changes to this project are recorded here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches v1.0.0. Until then, minor version bumps may include breaking
changes (documented in their release notes).

## [Unreleased]

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
