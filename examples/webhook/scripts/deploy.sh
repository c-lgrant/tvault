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
# pipefail is not POSIX sh; the wrangler exit code is checked via the log instead

cd "$(dirname "$0")/.."
# Capture wrangler's output to find the deployed URL for ensure-seed, and echo it
# back. No `tee /dev/stderr` — that path does not exist in the Workers Builds
# sandbox and, under `set -e`, took the whole deploy down (2026-09-21).
log=$(mktemp)
rc=0; wrangler deploy src/runtime/worker.ts > "$log" 2>&1 || rc=$?
cat "$log"
[ "$rc" -eq 0 ] || { rm -f "$log"; exit "$rc"; }
WEBHOOK_URL=$(grep -oE "https://[a-z0-9.-]+\.workers\.dev" "$log" | head -1 || true)
rm -f "$log"
export WEBHOOK_URL
# Seed provisioning is best-effort: if the build's wrangler token lacks Workers
# Scripts: Edit, the deploy still succeeds and the operator sets the seed by hand
# (the /bind setup page shows how). Non-fatal so a missing scope never reds the build.
sh scripts/ensure-seed.sh || echo "deploy: ensure-seed skipped (no Secret-set permission) — set TV_WEBHOOK_SEED manually (see the /bind setup page or deploy/cloudflare/README.md)."
