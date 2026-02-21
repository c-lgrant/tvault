#!/bin/sh
set -eu

: "${NGROK_AUTHTOKEN:?NGROK_AUTHTOKEN is required}"
: "${NGROK_URL:?NGROK_URL is required}"

# Always use the ngrok public URL as the external URL so that
# /bind and /v1/register-url generate correct registration links,
# even when accessed via local IP.
export WEBHOOK_EXTERNAL_URL="${WEBHOOK_EXTERNAL_URL:-https://${NGROK_URL#https://}}"

gunicorn -k uvicorn.workers.UvicornWorker \
  --bind "0.0.0.0:${PORT}" \
  --workers 1 \
  --threads 1 \
  main:app &

APP_PID=$!

ngrok config add-authtoken "${NGROK_AUTHTOKEN}"

ngrok http "http://127.0.0.1:${PORT}" --url="${NGROK_URL}" --log=stdout &
NGROK_PID=$!

# Exit if either process dies (portable alternative to `wait -n`)
while kill -0 "$APP_PID" 2>/dev/null && kill -0 "$NGROK_PID" 2>/dev/null; do
  sleep 1
done

# If we got here, one died; stop the other and exit non-zero
kill "$APP_PID" "$NGROK_PID" 2>/dev/null || true
exit 1