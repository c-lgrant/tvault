# Cloudflare Workers Deploy

Deploy the webhook (the credential **data plane**) to Cloudflare Workers. The
AES-256 key + HMAC secret are HKDF-derived in memory from a single seed secret
(`TV_WEBHOOK_SEED`) — they are never persisted, and stable across redeploys.

## One-click deploy (button)

Click **Deploy to Workers** in the top-level [`../../README.md`](../../README.md)
(or from the Token Vault onboarding screen). Cloudflare forks the repo into your
account and walks you through setup.

What to expect during the wizard:

1. **KV namespaces are auto-provisioned.** `wrangler.toml` declares `REPLAY` and
   `TOKENS` with default placeholder IDs in real (hex) namespace-id format, so
   Cloudflare creates a **fresh, uniquely-named namespace for each** and rewrites
   the IDs in the deployed config. A new namespace is made every deploy, so
   **repeat clicks never collide** ("already exists"). No prompts to select.
2. **Deploy** finishes and gives you a `https://<name>.<account>.workers.dev` URL.

Then finish setup (the button does **not** do these):

3. **Set the seed secret** — the webhook can't bind until this exists:
   ```bash
   openssl rand -hex 32 | wrangler secret put TV_WEBHOOK_SEED
   ```
   (Or Worker → Settings → Variables → add `TV_WEBHOOK_SEED` as a Secret.)
4. **Bind to Token Vault** — open `https://<your-worker>.workers.dev/bind` and
   follow it through. It mints a one-time code and redirects to Token Vault's
   `/vault/webhook-bind`, which calls `POST /v1/exchange` to fetch the HMAC
   secret and verifies its hash. Done — the control plane is now paired with
   your webhook.

## Manual deploy (CLI)

```bash
# 1. Authenticate
wrangler login

# 2. Create the two KV namespaces, then paste the returned IDs into wrangler.toml
wrangler kv namespace create REPLAY
wrangler kv namespace create TOKENS

# 3. Set the seed secret (required). OAUTH_PROVIDERS_JSON is optional — only
#    needed for autonomous OAuth refresh (/v1/refresh-notify).
openssl rand -hex 32 | wrangler secret put TV_WEBHOOK_SEED
# wrangler secret put OAUTH_PROVIDERS_JSON   # optional

# 4. Deploy
npm run deploy
```

Non-secret config (`TOKENVAULT_FRONTEND_URL`, optional `TOKENVAULT_IP`,
`DENY_IPS`/`DENY_ORIGINS`) lives in `wrangler.toml` under `[vars]`.

## D1 instead of KV for tokens (optional)

KV is the default for credential storage. For durable, strongly-consistent
refresh writes, use a D1 database instead: create it, uncomment the
`[[d1_databases]]` block in `wrangler.toml` (binding `DB`), and drop the `TOKENS`
KV binding. The runtime picks D1 automatically when a `DB` binding is present.

## Post-deploy bind URL

```
https://<your-worker>.workers.dev/bind
```
