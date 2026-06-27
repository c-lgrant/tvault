#!/bin/sh
set -eu

: "${PORT:=8080}"
: "${TUNNEL:=none}"

# Start the Node runtime in the background
node --import tsx/esm src/runtime/node.ts &
APP_PID=$!

case "${TUNNEL}" in
  ngrok)
    : "${NGROK_AUTHTOKEN:?NGROK_AUTHTOKEN is required when TUNNEL=ngrok}"
    : "${NGROK_URL:?NGROK_URL is required when TUNNEL=ngrok}"

    export WEBHOOK_EXTERNAL_URL="${WEBHOOK_EXTERNAL_URL:-https://${NGROK_URL#https://}}"

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

    NGROK_ARGS="http http://127.0.0.1:${PORT} --url=${NGROK_URL} --log=stdout"

    if [ -n "${TOKENVAULT_IP:-}" ] && [ -f /app/traffic-policy.yaml ]; then
      POLICY_FILE="/tmp/traffic-policy.yaml"
      sed "s/\${TOKENVAULT_IP}/${TOKENVAULT_IP}/g" /app/traffic-policy.yaml > "${POLICY_FILE}"
      NGROK_ARGS="${NGROK_ARGS} --traffic-policy-file=${POLICY_FILE}"
      echo "ngrok: IP policy active — denying ${TOKENVAULT_IP} on /v1/credential and /v1/store"
    else
      echo "ngrok: no TOKENVAULT_IP set — traffic policy not applied"
    fi

    # shellcheck disable=SC2086
    ngrok ${NGROK_ARGS} &
    TUNNEL_PID=$!
    ;;

  cloudflared)
    : "${CF_TUNNEL_TOKEN:?CF_TUNNEL_TOKEN is required when TUNNEL=cloudflared}"

    cloudflared tunnel --no-autoupdate run --token "${CF_TUNNEL_TOKEN}" &
    TUNNEL_PID=$!
    ;;

  none)
    echo "TUNNEL=none: running without a tunnel (direct port ${PORT} only)"
    # No tunnel process; wait on app only
    wait "$APP_PID"
    exit $?
    ;;

  *)
    echo "Unknown TUNNEL value '${TUNNEL}'. Use ngrok, cloudflared, or none." >&2
    exit 1
    ;;
esac

# Exit if either process dies (portable — no wait -n)
while kill -0 "$APP_PID" 2>/dev/null && kill -0 "$TUNNEL_PID" 2>/dev/null; do
  sleep 1
done

kill "$APP_PID" "$TUNNEL_PID" 2>/dev/null || true
exit 1
