#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

ENV_FILE="agentsmith.env"
CFG_FILE="config.yaml"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "error: $ENV_FILE not found." >&2
  echo "  Copy agentsmith.env.example to agentsmith.env and fill in your secrets." >&2
  exit 1
fi

if [[ ! -f "$CFG_FILE" ]]; then
  echo "error: $CFG_FILE not found." >&2
  echo "  Copy config.example.yaml to config.yaml and adjust as needed." >&2
  exit 1
fi

set -a
. "./$ENV_FILE"
set +a

exec ./agentsmith -f "$CFG_FILE" "$@"
