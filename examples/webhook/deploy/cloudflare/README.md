# Cloudflare Workers Deploy

Deploy the webhook (the credential **data plane**) to Cloudflare Workers. The
AES-256 key + HMAC secret are HKDF-derived in memory from a single seed secret
(`TV_WEBHOOK_SEED`) — they are never persisted, and stable across redeploys.

## One-click deploy (button)

Click **Deploy to Workers** in the top-level [`../../README.md`](../../README.md)
(or from the Token Vault onboarding screen). Cloudflare forks the repo into your
account and walks you through setup.

What to expect during the wizard:

1. **One KV namespace.** `wrangler.toml` declares a single `KV` binding (it backs
   replay protection — request IDs + ticket nonces). The wizard shows one
   **"Select KV namespace"** step:
   - **First deploy:** choose **Create new** — Cloudflare makes the namespace and
     rewrites the id in the deployed config.
   - **Re-deploying** (or if a leftover `tv-webhook` namespace exists from an
     earlier attempt): choose the **existing** namespace instead of creating a new
     one. The wizard names new namespaces after the worker (`tv-webhook`), so
     "Create new" a second time fails with *"already exists"* — selecting the
     existing one avoids that.
2. **One D1 database.** `wrangler.toml` declares a `DB` binding for credential
   storage. The wizard shows a **"Create D1 database"** step — same pattern:
   **Create new** on the first deploy, or pick the **existing** `tv-webhook` db
   when re-deploying. (A KV namespace and a D1 db can both be named `tv-webhook`
   without colliding — different resource types.) The `kv` table self-creates on
   the first request; there is no migration step.
3. **Deploy** finishes and gives you a `https://<name>.<account>.workers.dev` URL.

Then finish setup (the button does **not** do these):

4. **Provide the seed** — the webhook needs one root seed before it can bind.
   Open `https://<your-worker>.workers.dev/bind`; if no seed is set it shows a
   setup page with two choices:
   - **Generate & save (one-click)** — the page mints a random seed and stores it
     in KV (key `seed:v1`). Fastest; good for dev. The seed is readable to anyone
     with KV access (credentials live in D1, so a leak of one store alone can't
     decrypt).
   - **Workers Secret (hardened, recommended for prod)** — set `TV_WEBHOOK_SEED`
     as an encrypted Secret (the page deep-links to Settings, or use the CLI):
     ```bash
     openssl rand -hex 32 | wrangler secret put TV_WEBHOOK_SEED --name <worker>
     ```
     A Secret always takes precedence over a generated one.

   > **Choose before you bind.** The seed is the root key — changing it after a
   > bind changes the HMAC secret and forces a re-bind. To move generated → Secret
   > without re-binding, set the Secret to the *same* value (read it from
   > Workers & Pages → KV → `seed:v1`).
5. **Bind to Token Vault** — back on `/bind` (now that a seed exists), click
   **Connect**. It mints a one-time code and redirects to Token Vault's
   `/vault/webhook-bind`, which calls `POST /v1/exchange` to fetch the HMAC
   secret and verifies its hash. Done — the control plane is now paired with
   your webhook.

## Manual deploy (CLI)

```bash
# 1. Authenticate
wrangler login

# 2. Create the KV namespace (replay) and the D1 db (storage), then paste the
#    returned ids into wrangler.toml (kv_namespaces.id / d1_databases.database_id)
wrangler kv namespace create KV
wrangler d1 create tv-webhook

# 3. Set the seed (hardened path). Optional if you'll click "Generate & save" on
#    /bind instead. OAUTH_PROVIDERS_JSON is optional — only for autonomous OAuth
#    refresh (/v1/refresh-notify).
openssl rand -hex 32 | wrangler secret put TV_WEBHOOK_SEED
# wrangler secret put OAUTH_PROVIDERS_JSON   # optional

# 4. Deploy
npm run deploy
```

Non-secret config (`TOKENVAULT_FRONTEND_URL`, optional `TOKENVAULT_IP`,
`DENY_IPS`/`DENY_ORIGINS`) lives in `wrangler.toml` under `[vars]`.

## Storage: D1 for credentials, KV for replay

This template stores credentials in **D1** (binding `DB`) — durable and
strongly-consistent, which matters for refresh writes — and uses **KV** (binding
`KV`) for replay protection (request IDs + ticket nonces). Both are declared in
`wrangler.toml`; the wizard/CLI provisions both. The runtime auto-selects D1 for
storage whenever a `DB` binding is present and falls back to KV-only storage if
you remove the `DB` binding. KV is required either way.

## Seed custody & the security tradeoff

The AES-256 encryption key, the HMAC signing secret, and the webhook id are all
HKDF-derived in memory from one root **seed** — Token Vault never sees the key,
only the HMAC secret (via the one-time `/v1/exchange`). Where the seed lives is
your choice:

| Path | Where the seed lives | At-rest exposure | Use |
|---|---|---|---|
| **Workers Secret** (`TV_WEBHOOK_SEED`) | Encrypted Secret store | Write-only, not readable | Production |
| **Generate & save** (button on `/bind`) | KV (`seed:v1`) | Readable with KV access | Dev / quick start |

Blast-radius split: the seed is in **KV**, credentials are in **D1** — a leak of
*either* store alone decrypts nothing; you need both. A `TV_WEBHOOK_SEED` Secret
always wins over a generated seed.

**Consequence of changing the seed after binding:** the derived HMAC secret
changes, so the hash Token Vault pinned at bind no longer matches and every call
fails until you **re-bind**. To move generated → Secret without re-binding, set
the Secret to the *same* value (copy it from Workers & Pages → KV → `seed:v1`),
then the generated copy is ignored.

### Auto-provision the seed as a Secret at deploy (zero-touch — default)

Best of both worlds — a **real encrypted Secret**, set with **no manual step and
no dashboard config**. The canonical `deploy` script *is* the seed-provisioning
one: `npm run deploy` → `scripts/deploy.sh` runs `wrangler deploy`, then
`scripts/ensure-seed.sh`, which mints a seed and stores it as `TV_WEBHOOK_SEED`
**only if one isn't already set** (idempotent — it never rotates an existing seed,
so re-running on every push is safe).

**Workers Builds picks this up automatically.** Cloudflare reads `package.json`
and pre-populates the build/deploy fields from your `build` and `deploy` scripts —
so the Deploy-to-Workers flow runs `npm run deploy` (i.e. `scripts/deploy.sh`)
without you touching the dashboard. No "deploy command" to set by hand.

`wrangler secret put` needs **Workers Scripts: Edit**. If the build's wrangler
token has it, the seed lands as a Secret on the first build and you can skip the
`/bind` "Generate & save" button entirely. If it doesn't, `ensure-seed` is
**non-fatal** — the deploy still succeeds and you fall back to the KV path on
`/bind`. To force the Secret path, add a `CLOUDFLARE_API_TOKEN` build variable
(Workers Scripts: Edit) under Settings → Builds → Variables and Secrets.

> The token lives in **CI only — never in the Worker**. A Worker can't set its own
> Secret at runtime (Secrets are deploy-time, read-only bindings; setting one is a
> privileged API call). Doing it from the build keeps that privilege in CI, where
> it belongs, and gives you Secret-grade custody without the KV fallback.

## Logs & traces (observability)

`wrangler.toml` enables `[observability]`, so the worker persists structured logs
and per-invocation traces. View them in **Workers & Pages → this worker → Logs**
(a.k.a. Observability), or stream live:

```bash
wrangler tail --name <worker>
```

`head_sampling_rate = 1` keeps 100% of invocations — lower it for high traffic.

## Post-deploy bind URL

```
https://<your-worker>.workers.dev/bind
```
