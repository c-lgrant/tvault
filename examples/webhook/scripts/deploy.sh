#!/bin/sh
# Deploy the worker, then auto-provision the seed as an encrypted Secret.
#
# This is the repo's canonical `deploy` script (`npm run deploy`). Workers Builds
# auto-detects the `deploy` script from package.json and runs it, so this provisions
# the seed with no dashboard config — a fully bindable webhook whose seed is a real
# Secret, no manual `wrangler secret put`, no /bind button step. Run it locally too.
#
# Order matters: `wrangler secret put` needs the script to already exist, so we
# deploy first and provision the seed second (ensure-seed.sh is idempotent, so
# the seed is minted on the first build and left alone on every build after).
#
# Requires a wrangler auth context with Workers Scripts: Edit (a CLOUDFLARE_API_TOKEN
# build variable in CI, or `wrangler login` locally).
set -eu
cd "$(dirname "$0")/.."
wrangler deploy src/runtime/worker.ts
# Seed provisioning is best-effort: if the build's wrangler token lacks Workers
# Scripts: Edit, the deploy still succeeds and the operator falls back to the
# /bind "Generate & save" (KV) path. Non-fatal so a missing scope never reds the build.
sh scripts/ensure-seed.sh || echo "deploy: ensure-seed skipped (no Secret-set permission) — use /bind 'Generate & save' or set TV_WEBHOOK_SEED manually."
