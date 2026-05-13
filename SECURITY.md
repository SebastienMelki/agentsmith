# Security Policy

agentsmith brokers MCP traffic between clients and backend services that may
hold privileged credentials (API keys, OAuth tokens, webhook secrets). We take
security reports seriously.

## Reporting a vulnerability

**Please do not file public GitHub issues for security problems.**

Email **sebastienmelki@gmail.com** with:

- A description of the issue and its impact.
- Steps to reproduce, or a minimal proof-of-concept.
- Affected version (commit SHA or tag).
- Whether the issue is already publicly known.

You can expect:

- An acknowledgement within **3 business days**.
- A triage assessment and remediation plan within **10 business days**.
- Coordinated disclosure: a fix is released before details are made public.

If you do not receive a response within the windows above, feel free to open
a GitHub issue saying only "I sent a security report on `<date>` — please
check your inbox" (without details).

## Scope

In scope:

- Credential leakage between configured backends (the project's central
  isolation guarantee).
- Header / token injection via crafted MCP requests.
- Bypass of the `${VAR}` interpolation safety check that refuses to start
  with unset secrets.
- Memory-safety, panic, or crash issues reachable from MCP clients or the
  admin server.
- Supply-chain concerns in the build (`go.mod`, `go.sum`).

Out of scope:

- Issues in upstream MCP backends (report to their maintainers).
- Misconfiguration where the operator exposes the admin port (`adminAddr`,
  default `:3002`) to a public network. The admin port has no authentication
  and, in `protected` mode, also issues MCP credentials via `POST /users` —
  exposing it is equivalent to full auth bypass on the MCP endpoint. Keep it
  on `127.0.0.1` or behind a firewall.
- Denial of service through resource exhaustion in unauthenticated test
  deployments.

## Supported versions

agentsmith is pre-1.0. Only the latest tagged release receives security
fixes. Pin to a tag (not `main`) for production use, and watch the
[Releases](https://github.com/sebastienmelki/agentsmith/releases) page.
