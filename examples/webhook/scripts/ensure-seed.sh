#!/bin/sh
# Ensure TV_WEBHOOK_SEED exists as a Worker Secret.
#
# Idempotent: it generates a fresh 32-byte seed ONLY when none is set. Re-running
# it (Workers Builds runs on every push) therefore never rotates an existing seed
# — rotating would change the derived HMAC secret and break the Token Vault bind.
#
# Requires wrangler to be authenticated with permission to read + set Worker
# secrets (Workers Scripts: Edit):
#   - Workers Builds / CI: set a CLOUDFLARE_API_TOKEN build variable with that scope.
#   - Locally: `wrangler login` is enough.
# Targets the script named in wrangler.toml; override with WORKER_NAME.
#
# Note: `wrangler secret put` targets an EXISTING script, so run this AFTER a
# `wrangler deploy` (see deploy.sh). Setting the secret rolls a new version that
# includes it.
set -eu

name_arg=""
[ -n "${WORKER_NAME:-}" ] && name_arg="--name ${WORKER_NAME}"

# `secret list` prints a JSON array of {name,type}. If our key is already there,
# leave it untouched.
if wrangler secret list $name_arg 2>/dev/null | grep -q '"TV_WEBHOOK_SEED"'; then
  echo "ensure-seed: TV_WEBHOOK_SEED already set — leaving as-is."
  exit 0
fi

echo "ensure-seed: TV_WEBHOOK_SEED not set — generating a 32-byte seed and storing it as a Secret."
openssl rand -hex 32 | wrangler secret put TV_WEBHOOK_SEED $name_arg
echo "ensure-seed: done."
