#!/bin/sh
# Deploy the worker, then auto-provision the seed as an encrypted Secret.
#
# Use this as the Workers Builds "deploy command" (or run `npm run deploy:auto`
# locally) to get a fully provisioned, bindable webhook whose seed is a real
# Secret — no KV fallback, no manual `wrangler secret put`, no /bind button step.
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
sh scripts/ensure-seed.sh
