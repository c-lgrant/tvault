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

# Write ngrok config — authtoken + web inspector toggle
NGROK_CONFIG="/root/.config/ngrok/ngrok.yml"
mkdir -p "$(dirname "${NGROK_CONFIG}")"

if [ -n "${WI_PORT:-}" ]; then
  cat > "${NGROK_CONFIG}" <<EOF
version: "3"
agent:
    authtoken: ${NGROK_AUTHTOKEN}
    web_addr: 0.0.0.0:${WI_PORT}
EOF
  echo "ngrok: web inspector enabled on port ${WI_PORT}"
else
  cat > "${NGROK_CONFIG}" <<EOF
version: "3"
agent:
    authtoken: ${NGROK_AUTHTOKEN}
    web_addr: false
EOF
  echo "ngrok: web inspector disabled (set WI_PORT to enable)"
fi

# Build ngrok args — apply traffic policy if TOKENVAULT_IP is set
NGROK_ARGS="http http://127.0.0.1:${PORT} --url=${NGROK_URL} --log=stdout"

if [ -n "${TOKENVAULT_IP:-}" ] && [ -f /app/traffic-policy.yaml ]; then
  # Substitute the Token Vault IP into the policy template
  POLICY_FILE="/tmp/traffic-policy.yaml"
  sed "s/\${TOKENVAULT_IP}/${TOKENVAULT_IP}/g" /app/traffic-policy.yaml > "${POLICY_FILE}"
  NGROK_ARGS="${NGROK_ARGS} --traffic-policy-file=${POLICY_FILE}"
  echo "ngrok: IP policy active — denying ${TOKENVAULT_IP} on /v1/credential and /v1/store"
else
  echo "ngrok: no TOKENVAULT_IP set — traffic policy not applied"
fi

# shellcheck disable=SC2086
ngrok ${NGROK_ARGS} &
NGROK_PID=$!

# Exit if either process dies (portable alternative to `wait -n`)
while kill -0 "$APP_PID" 2>/dev/null && kill -0 "$NGROK_PID" 2>/dev/null; do
  sleep 1
done

# If we got here, one died; stop the other and exit non-zero
kill "$APP_PID" "$NGROK_PID" 2>/dev/null || true
exit 1
