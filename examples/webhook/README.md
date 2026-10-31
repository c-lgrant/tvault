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

## Connect with your own OAuth app (`oauth-callback`)

The webhook can finish an OAuth consent itself, so the provider's authorization
code, access token and refresh token never pass through the control plane.

1. Register an OAuth app at the provider (Google, GitHub and Spotify work out of
   the box). Set its redirect URI to `https://<your-webhook>/v1/oauth/callback`.
2. Give the webhook the client secret, in `OAUTH_PROVIDERS_JSON` (a Secret on
   Workers), keyed by the lower-case provider name:
   ```json
   { "google": { "clientId": "…", "clientSecret": "…" } }
   ```
   `clientId` is optional (the control plane sends the id you saved there; if you
   set it here it must match). `tokenUrl` and `authorizeUrl` are only needed for
   a provider outside the built-in table (`google`, `github`, `spotify`). The
   client secret is only ever sent to a token URL from this config or that
   table; a state ticket, stored hint or refresh hint naming another URL is
   refused.
3. Save the same client id in Token Vault and press Connect. The control plane
   signs a one-shot, 10-minute state ticket and sends the browser to
   `/v1/oauth/start?state=…` on the webhook. That verifies the state, sets a
   short-lived `HttpOnly; Secure; SameSite=Lax` cookie bound to the ticket's
   nonce and redirects to the provider, so only the browser that started the
   flow can finish it. The provider redirects back to `/v1/oauth/callback`,
   where the webhook checks the state and the cookie, exchanges the code (PKCE S256; the verifier is
   derived from the webhook's HMAC secret and the ticket nonce and never travels
   via the browser), stores the token under the service name the ticket names,
   and redirects the browser to `<TOKENVAULT_FRONTEND_URL>/tokens/oauth-result`
   with only a status, the service name and a short error code.

The stored token records a non-secret `oauth` hint (`provider`, `tokenUrl`,
`clientId`) in its meta, so `/v1/refresh-notify` can refresh it with the same
`OAUTH_PROVIDERS_JSON` entry. The state ticket is the usual
`base64url(json).hex_hmac` with `pur: "oauth_connect"` and the extra fields `prv`
(provider), `tku` (token URL, cross-checked), `clid` (client id), `rdu`
(redirect URI) and `scp` (space-separated scopes). It may also carry the store
constraints `mode` (`create` refuses an existing service with `already_exists`)
and `cid` (stored as `meta.creationId`), applied as `/v1/store` applies them.

## Tests

```bash
npm run typecheck       # tsc --noEmit
npm test                # vitest: conformance + modules + security
sh test/smoke/run.sh    # local Node HTTP E2E round-trip
```

## Upgrading

Upgrades are an in-place redeploy — no migration, no re-keying, no URL change.
Run the **Update webhook** GitHub Action in your repo to open a PR, merge it, and
Workers Builds redeploys against your existing D1 + seed. See
[deploy/cloudflare/UPGRADING.md](deploy/cloudflare/UPGRADING.md).

## License

[MIT](../../LICENSE) — Token Vault project.
