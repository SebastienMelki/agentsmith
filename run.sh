#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
set -a
. ./agentsmith.env
set +a
exec ./agentsmith -f config.yaml "$@"
