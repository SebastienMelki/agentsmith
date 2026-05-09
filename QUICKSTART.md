# agentsmith quickstart

Three containers, one federated MCP endpoint. Friend-friendly: the dodo and slack backends run **with zero secrets** — agentsmith holds the keys and injects them per-request as headers, scoped to each backend.

## Prerequisites

- **Docker Desktop** (or Docker Engine on Linux). On Mac/Windows, enable host networking: *Settings → Resources → Network → Enable host networking*.
- **A Slack bot token** (`xoxb-…`) — create a Slack app at https://api.slack.com/apps and grab the bot OAuth token.
- **Dodo Payments credentials** — API key and webhook key from https://dodopayments.com.

## 1 — Drop a config file

```bash
cat > config.yaml <<'EOF'
listenAddr: ":3001"
path: /mcp

targets:
  - name: dodo
    url: http://127.0.0.1:8765/mcp
    headers:
      X-Dodo-API-Key: ${DODO_PAYMENTS_API_KEY}
      X-Dodo-Webhook-Key: ${DODO_PAYMENTS_WEBHOOK_KEY}

  - name: slack
    url: http://127.0.0.1:8766/mcp
    headers:
      X-Slack-Token: ${SLACK_TOKEN}
EOF
```

## 2 — Export your credentials

```bash
export DODO_PAYMENTS_API_KEY=sk_test_or_live_...
export DODO_PAYMENTS_WEBHOOK_KEY=whsec_...
export SLACK_TOKEN=xoxb-...
```

## 3 — Run the three containers

```bash
# dodo-mcp on :8765 — no creds needed; agentsmith injects them per-request
docker run -d --name dodo-mcp --network=host \
  sebastienmelki/dodopayments-mcp:latest

# slack-mcp on :8766 — same deal
docker run -d --name slack-mcp --network=host \
  sebastienmelki/slack-mcp:latest

# agentsmith on :3001 (MCP) and :3002 (admin UI)
docker run --rm --name agentsmith --network=host \
  -v "$PWD/config.yaml:/etc/agentsmith/config.yaml:ro" \
  -e DODO_PAYMENTS_API_KEY \
  -e DODO_PAYMENTS_WEBHOOK_KEY \
  -e SLACK_TOKEN \
  sebastienmelki/agentsmith:latest
```

The `agentsmith` container runs in the foreground so you can watch the logs. Ctrl+C to stop it.

## 4 — Verify

- **Federated MCP endpoint**: `http://localhost:3001/mcp` (point any MCP client at this URL).
- **Admin dashboard**: open `http://localhost:3002` in your browser — both backends should show as `connected`, with their tool counts and live metrics.

## 5 — Stop everything

```bash
docker stop dodo-mcp slack-mcp && docker rm dodo-mcp slack-mcp
# agentsmith was --rm, so Ctrl+C already cleaned it up
```

## Tips

- Using a Dodo **test** API key (`sk_test_…`)? Add `-e DODO_PAYMENTS_ENVIRONMENT=test` to the `dodo-mcp` run.
- Both backends run with all Linux capabilities dropped, read-only filesystem, and as a non-root user (UID 65532). Same for agentsmith.
- All three images are multi-arch (amd64 + arm64) and ~4 MB compressed.
