#!/bin/bash
set -euo pipefail

API_KEY="mcp-nginx-bouncer-test-key"
BOUNCER_NAME="mcp-nginx-bouncer"

/bin/bash /docker_start.sh "$@" &
PID=$!
trap 'kill "$PID" 2>/dev/null || true' EXIT

for _ in $(seq 1 90); do
    if cscli lapi status >/dev/null 2>&1; then
        break
    fi
    sleep 2;
done

if ! cscli lapi status >/dev/null 2>&1; then
    echo "CrowdSec LAPI did not become ready in time" >&2
    wait "$PID"
    exit 1
fi

cscli bouncers delete "$BOUNCER_NAME" >/dev/null 2>&1 || true
cscli bouncers add "$BOUNCER_NAME" -k "$API_KEY"

trap - EXIT
wait "$PID"
exit $?
