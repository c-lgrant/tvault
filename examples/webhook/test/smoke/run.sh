#!/bin/sh
# Local E2E smoke for the Node runtime. Starts the server with throwaway key +
# store paths (no /data writes), runs the client round-trip, and tears down.
set -eu

PORT="${PORT:-8799}"
TMP="$(mktemp -d)"
trap 'kill "${SERVER_PID:-}" 2>/dev/null || true; rm -rf "${TMP}"' EXIT

echo "smoke: starting node runtime on :${PORT} (store=${TMP})"
TOKENVAULT_STORE_PATH="${TMP}/secret.json" \
TOKENVAULT_KV_STORE_PATH="${TMP}/kv.json" \
EXTERNAL_URL="http://127.0.0.1:${PORT}" \
TOKENVAULT_FRONTEND_URL="http://127.0.0.1:${PORT}" \
PORT="${PORT}" \
TUNNEL=none \
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

PORT="${PORT}" npx tsx test/smoke/client.ts
