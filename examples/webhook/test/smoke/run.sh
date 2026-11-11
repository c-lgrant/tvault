#!/bin/sh
# Local E2E smoke for the Node runtime. Starts the server with throwaway key +
# store paths (no /data writes), runs the client round-trip, and tears down.
#
# Two runs. The first uses default settings and checks that /v1/proxy refuses
# the loopback upstream. The second allows private upstreams and sets an origin
# allowlist, then runs the full round-trip.
set -eu

PORT="${PORT:-8799}"
TMP="$(mktemp -d)"
trap 'kill "${SERVER_PID:-}" 2>/dev/null || true; rm -rf "${TMP}"' EXIT

# start_server <name> [VAR=value ...]: start the Node runtime and wait for health.
start_server() {
  name="$1"
  shift
  mkdir -p "${TMP}/${name}"
  echo "smoke: starting node runtime on :${PORT} (${name})"
  env \
    TOKENVAULT_STORE_PATH="${TMP}/${name}/secret.json" \
    TOKENVAULT_KV_STORE_PATH="${TMP}/${name}/kv.json" \
    EXTERNAL_URL="http://127.0.0.1:${PORT}" \
    TOKENVAULT_FRONTEND_URL="http://127.0.0.1:${PORT}" \
    PORT="${PORT}" \
    TUNNEL=none \
    "$@" \
    npx tsx src/runtime/node.ts &
  SERVER_PID=$!

  # Wait for the server to answer health (max ~10s).
  i=0
  until curl -fsS "http://127.0.0.1:${PORT}/v1/health" >/dev/null 2>&1; do
    i=$((i + 1))
    if [ "${i}" -gt 50 ]; then
      echo "smoke: server did not become ready" >&2
      exit 1
    fi
    sleep 0.2
  done
}

stop_server() {
  kill "${SERVER_PID}" 2>/dev/null || true
  wait "${SERVER_PID}" 2>/dev/null || true
  # The port must be free before the next run (max ~10s).
  i=0
  while curl -fsS "http://127.0.0.1:${PORT}/v1/health" >/dev/null 2>&1; do
    i=$((i + 1))
    if [ "${i}" -gt 50 ]; then
      echo "smoke: server did not stop" >&2
      exit 1
    fi
    sleep 0.2
  done
}

start_server defaults
PORT="${PORT}" SMOKE_EXPECT_PRIVATE_REFUSED=1 npx tsx test/smoke/client.ts
stop_server

start_server allowed \
  TV_PROXY_ALLOW_PRIVATE=true \
  TV_PROXY_ALLOWED_ORIGINS="{\"github\":[\"http://127.0.0.1:${PORT}\"]}"
PORT="${PORT}" npx tsx test/smoke/client.ts
