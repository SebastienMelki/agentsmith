# Contributing to agentsmith

Thanks for your interest in contributing. agentsmith is small and opinionated;
this document covers what you need to know to send a useful patch.

## Ground rules

- **No CLA, no DCO.** A regular GitHub PR with a clear description is enough.
- **Be excellent to each other.** See [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
- **Security issues:** do not file a public issue. See [`SECURITY.md`](SECURITY.md).

## Development setup

You need:

- **Go 1.25+** (matches `go.mod`)
- **[golangci-lint v2](https://golangci-lint.run/welcome/install/)** for `make lint`
- A working MCP backend if you want to run the gateway end-to-end (any MCP
  server speaking Streamable HTTP works — see `examples/`).

Clone and verify the toolchain:

```bash
git clone https://github.com/sebastienmelki/agentsmith.git
cd agentsmith
make build
make test
make lint
```

If those three commands succeed, you're ready.

## Workflow

1. Open an issue (or comment on an existing one) before starting non-trivial
   work, so we can sort out direction before code is written.
2. Fork, branch from `main`, keep the branch focused on one change.
3. Run `make fmt && make lint && make test` before pushing.
4. Open a PR; the GitHub Actions CI workflow re-runs lint, test, and build.

### Commit messages

Follow the existing style — short imperative subject, optional body explaining
*why* the change is needed:

```
gateway: drop redundant header copy in headerInjector

The map iteration already covers every entry; the second loop was
left over from an earlier draft.
```

The recent `git log` is the source of truth.

## What we accept

Likely accepted:

- Bug fixes with a regression test.
- New backend examples in `examples/<name>/` following the existing shape
  (`config.yaml` + `.env.example` + a leading comment block explaining the
  backend).
- Test coverage improvements, especially for `internal/gateway`.
- Documentation fixes and clarity improvements.
- Linter-clean refactors that reduce code without changing behavior.

Likely declined (open an issue first):

- New runtime dependencies. Three direct deps is intentional; each new one
  needs justification.
- Auth, rate-limiting, or per-user scoping. agentsmith is a federation
  primitive, not a full API gateway — these belong in a layer above.
- Vendor-specific MCP extensions. Stay close to the spec.

## Code conventions

The toolchain enforces most of what matters; reading `.golangci.yml` is the
fastest way to internalize the rules. A few that aren't strictly mechanical:

- **slog logging** — key-value pairs only, snake_case keys (enforced by
  `sloglint`). Example: `slog.Info("backend connected", "name", b.name)`.
- **No new globals** unless there's a real reason. The existing globals
  (`namespaceSep`, timeouts in `gateway/`) are deliberate.
- **Per-backend isolation is load-bearing.** Anything that touches
  `headerInjector`, `*http.Client` per backend, or the `Headers map` flow
  needs a test that proves backend A's headers do not leak to backend B.

## Adding a new backend example

`examples/` is intentionally lightweight. To add one:

```
examples/<your-backend>/
  config.yaml      # references ${VAR} for every secret; no real values
  .env.example     # one line per variable, with a placeholder value
```

Both files start with a comment block explaining what the backend is and
how to use the example. Cross-link the new example from the table in
`README.md`.

## Releasing (maintainers)

1. Update `CHANGELOG.md` — move entries from `[Unreleased]` to a new versioned
   section dated today.
2. Tag the commit: `git tag vX.Y.Z && git push --tags`.
3. GitHub Releases is populated from the tag.

## Questions

Open a GitHub Discussion for design questions, or an issue for anything
concrete. Slack and email are not maintained channels for this project.
