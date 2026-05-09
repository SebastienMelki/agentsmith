#!/usr/bin/env bash
# Run agentsmith from the published Docker image, replicating `make run`.
#
# Reads (both at repo root):
#   ./config.yaml      — same file `make run` uses, mounted as-is
#   ./agentsmith.env   — same env file (quotes are stripped before being
#                        passed to docker, since --env-file is literal)
#
# Uses --network=host, so the container reaches dodo/slack MCP backends
# at the same 127.0.0.1 addresses your config already points to.
#
# Override the image tag:
#   AGENTSMITH_TAG=0.1.0 scripts/docker-run.sh

set -euo pipefail

cd "$(cd "$(dirname "$0")/.." && pwd)"

if [[ ! -f config.yaml ]]; then
  echo "error: config.yaml not found in repo root" >&2
  echo "  cp examples/dodo-and-slack/config.yaml config.yaml" >&2
  exit 1
fi
if [[ ! -f agentsmith.env ]]; then
  echo "error: agentsmith.env not found in repo root" >&2
  echo "  cp examples/dodo-and-slack/.env.example agentsmith.env  # then fill in values" >&2
  exit 1
fi

# Use --network=host so 127.0.0.1 inside the container is the host's loopback.
# This is required because the MCP Go SDK auto-rejects requests whose Host
# header is non-loopback when the server is bound to a loopback address
# (DNS rebinding protection, SDK ≥v1.4). With host.docker.internal we'd hit
# that and get "Forbidden: invalid Host header" from each backend.
#
# Mac/Windows note: Docker Desktop ships host networking as opt-in. If the
# run errors with "host network is not enabled", turn it on under
# Settings → Resources → Network → Enable host networking, then re-run.
#
# Bonus: with host networking, -p flags are unnecessary — the container's
# binds are visible directly on the host.

# Docker's --env-file does NOT strip surrounding quotes the way godotenv
# (used by `make run`) does — KEY="value" would be passed to the container
# with the quote characters intact. Source the env file in bash (which
# handles quoting natively) and re-emit a quote-clean copy.
DOCKER_ENV=$(mktemp -t agentsmith-env.XXXXXX)
trap 'rm -f "$DOCKER_ENV"' EXIT
(
  set -a
  # shellcheck disable=SC1091
  . ./agentsmith.env
  set +a
  while IFS='=' read -r key _; do
    case "$key" in
      ''|\#*) continue ;;
    esac
    printf '%s=%s\n' "$key" "${!key}"
  done < agentsmith.env
) > "$DOCKER_ENV"

docker run --rm --name agentsmith \
  --network=host \
  -v "$PWD/config.yaml:/etc/agentsmith/config.yaml:ro" \
  --env-file "$DOCKER_ENV" \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  sebastienmelki/agentsmith:"${AGENTSMITH_TAG:-latest}"
