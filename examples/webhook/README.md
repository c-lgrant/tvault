# Token Vault Webhook — TS/Hono

A deployment-agnostic, multi-runtime Token Vault webhook server (the credential
**data plane**) built with [Hono](https://hono.dev). One runtime-neutral core,
two runtimes:

- **Node + ngrok** — container with an ngrok tunnel for rapid self-hosting
- **Node + Cloudflare Tunnel** — container with a cloudflared tunnel (no open ports)
- **Cloudflare Workers** — edge runtime, zero infra

Token Vault holds policy and identity; **this webhook holds the credentials**.
The control plane never sees your encryption key. Wire-compatible with the
Python reference in [`../webhook-ngrok/`](../webhook-ngrok/) (proven by the
conformance suite, which signs fixtures with the real Token Vault backend code).

## Project structure

```
src/
  core/
    protocol/       # types, errors, HMAC, tickets, replay
    crypto/         # AES-GCM, HMAC, HKDF, encoding (WebCrypto, shared)
    middleware/     # raw-body capture, HMAC auth, CORS, IP/origin denylist
    registry.ts     # feature-module + interceptor registry
    app.ts          # builds the Hono app from a RuntimeContext + modules
  modules/
    health, exchange, storage, credential, store, proxy,
    refreshNotify, tvRefresh
    interceptors/   # totp (capability + code gen), gcpSa (SA → access token)
  adapters/
    storage/        # fs (Node) | d1 (Workers)
    secrets/        # fileSecret (Node) | seedDerived (Workers, HKDF)
    replay/         # memory (Node) | cache (Workers, per-colo Cache API)
  runtime/
    config.ts       # shared env → WebhookConfig
    node.ts         # @hono/node-server entry
    worker.ts       # Cloudflare Workers entry
test/
  conformance/      # wire-parity vs the real Python contract
  modules/          # interceptor, refresh, and security-invariant tests
  smoke/            # local HTTP E2E (exchange → store → credential → proxy)
deploy/
  cloudflare/       # CF Workers deploy instructions
  tunnels/          # ngrok / cloudflared config stubs
```

## Quickstart — Node + tunnel

Keys are generated on first run and persisted to `/data` (kept stable by the
compose volume). Pick a tunnel mode:

```bash
# Local only, no tunnel:
TUNNEL=none docker compose up --build

# ngrok (set your reserved domain + authtoken):
NGROK_AUTHTOKEN=... NGROK_URL=https://your-name.ngrok.app \
TOKENVAULT_IP=<tv-egress-ip> TUNNEL=ngrok docker compose up --build

# Cloudflare Tunnel:
CF_TUNNEL_TOKEN=... TUNNEL=cloudflared docker compose up --build
```

Then open `https://<your-public-url>/bind` and click through to connect the
webhook to Token Vault (the one-time HMAC key exchange).

For pure local development without Docker:

```bash
npm install
npm run dev:node        # http://127.0.0.1:8080
```

## Deploy to Cloudflare Workers

On Workers the AES key + HMAC secret are HKDF-derived in memory from one root
seed (`TV_WEBHOOK_SEED`, a Workers Secret), stable across redeploys and never
persisted. Credentials live in **D1**; replay protection uses the per-colo
**Cache API** (no binding). The one-click button auto-provisions the D1 database
(its `database_id` is omitted from `wrangler.toml`, so Wrangler creates it on the
first deploy and reuses it on every push) and the seed Secret. CLI:

```bash
wrangler login
# Set the seed (encrypted, write-only Secret):
openssl rand -hex 32 | wrangler secret put TV_WEBHOOK_SEED
# Deploy — with database_id omitted, this auto-provisions the D1 database on the
# first run and reuses it thereafter (no id to paste into wrangler.toml):
npm run deploy
```

See [`deploy/cloudflare/README.md`](deploy/cloudflare/README.md) and
[`deploy/cloudflare/TUTORIAL.md`](deploy/cloudflare/TUTORIAL.md) for detail.

## Tests

```bash
npm run typecheck       # tsc --noEmit
npm test                # vitest: conformance + modules + security
sh test/smoke/run.sh    # local Node HTTP E2E round-trip
```

## License

[MIT](../../LICENSE) — Token Vault project.
