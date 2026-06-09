# Cloudflare Workers Deploy

Deploy the webhook (the credential **data plane**) to Cloudflare Workers. The
AES-256 key + HMAC secret are HKDF-derived in memory from a single seed secret
(`TV_WEBHOOK_SEED`) — never persisted, stable across redeploys.

The Worker needs exactly **one provisioned resource**: a **D1 database** for
credential storage. Replay protection uses the per-colo **Cache API** (no
binding, no quota), and the seed is a **Workers Secret** — so there is no KV
namespace to create.

## One-click deploy (button) — and push-to-deploy

Click **Deploy to Workers** in the top-level [`../../README.md`](../../README.md)
(or from the Token Vault onboarding screen). Cloudflare forks the repo into your
account, connects it to **Workers Builds**, and deploys. Every later `git push`
to the fork redeploys automatically.

What to expect:

1. **D1 is auto-provisioned.** `wrangler.toml` declares the `DB` binding with the
   `database_id` **omitted**, so Wrangler (≥4.45) creates a D1 database named
   `tv-webhook` on the first deploy and **keeps it linked on every later push** —
   the same database is reused, so a redeploy never loses your credentials and no
   account-specific id is baked into the template. The storage table self-creates
   on first request; there is no migration step.
2. **The seed Secret is auto-provisioned.** Workers Builds reads `package.json`
   and runs the `deploy` script (`npm run deploy` → `scripts/deploy.sh`), which
   deploys and then mints `TV_WEBHOOK_SEED` as an encrypted Secret **if one isn't
   already set** (idempotent — never rotated on later pushes). See *Seed custody*
   below; if the build token can't set Secrets, this step is skipped and you set
   the seed by hand (next step).
3. **Deploy** finishes with a `https://<name>.<account>.workers.dev` URL.

Then bind:

4. **Provide the seed (only if step 2 was skipped).** Open
   `https://<your-worker>.workers.dev/bind`; with no seed set it shows a setup
   page that walks you through adding `TV_WEBHOOK_SEED` as a Workers Secret
   (dashboard deep link + the exact `wrangler secret put` command).
5. **Bind to Token Vault** — on `/bind`, click **Connect**. It mints a one-time
   code and redirects to Token Vault's `/vault/webhook-bind`, which calls
   `POST /v1/exchange` to fetch the HMAC secret and verifies its hash. Done — the
   control plane is paired with your webhook.

## Manual deploy (CLI)

```bash
# 1. Authenticate
wrangler login

# 2. Set the seed (an encrypted, write-only Secret). OAUTH_PROVIDERS_JSON is
#    optional — only for autonomous OAuth refresh (/v1/refresh-notify).
openssl rand -hex 32 | wrangler secret put TV_WEBHOOK_SEED
# wrangler secret put OAUTH_PROVIDERS_JSON   # optional

# 3. Deploy. With database_id omitted, this auto-provisions the D1 database on
#    the first run and reuses it thereafter. (Or pre-create it with
#    `wrangler d1 create tv-webhook` — auto-provisioning links it by name.)
npm run deploy
```

Non-secret config (`TOKENVAULT_FRONTEND_URL`, optional `TOKENVAULT_IP`,
`DENY_IPS`/`DENY_ORIGINS`) lives in `wrangler.toml` under `[vars]`.

## Storage: D1 for credentials, Cache API for replay

Credentials are stored in **D1** (binding `DB`) — durable and strongly-consistent
(read-your-writes, which matters for refresh writes). Replay protection (request
IDs + ticket nonces) uses the Workers **Cache API**: per-colo and best-effort,
with no binding and no daily write quota. It's defence-in-depth — the primary
freshness bounds are the ticket's own short `exp` and the HMAC timestamp window —
so the per-colo nature is acceptable. D1 is the only resource the deploy
provisions.

## Seed custody & the security tradeoff

The AES-256 encryption key, the HMAC signing secret, and the webhook id are all
HKDF-derived in memory from one root **seed** — Token Vault never sees the key,
only the HMAC secret (via the one-time `/v1/exchange`). The seed is a **Workers
Secret** (`TV_WEBHOOK_SEED`): encrypted, write-only, not readable at rest, and
never in your repo. Nothing secret is ever written to a data store.

**Consequence of changing the seed after binding:** the derived HMAC secret
changes, so the hash Token Vault pinned at bind no longer matches and every call
fails until you **re-bind**. Settle the seed before you bind.

### Auto-provision the seed at deploy (zero-touch — default)

The canonical `deploy` script *is* the seed-provisioning one: `npm run deploy` →
`scripts/deploy.sh` runs `wrangler deploy`, then `scripts/ensure-seed.sh`, which
mints a seed and stores it as `TV_WEBHOOK_SEED` **only if one isn't already set**
(idempotent — it never rotates an existing seed, so re-running on every push is
safe).

**Workers Builds picks this up automatically.** Cloudflare reads `package.json`
and pre-populates the deploy field from your `deploy` script — so the
Deploy-to-Workers flow runs `npm run deploy` without you touching the dashboard.

`wrangler secret put` needs **Workers Scripts: Edit**. If the build's wrangler
token has it, the seed lands as a Secret on the first build and `/bind` shows the
**Connect** button straight away. If it doesn't, `ensure-seed` is **non-fatal** —
the deploy still succeeds and `/bind` shows the setup page so you can add the
Secret by hand. To force the auto path, add a `CLOUDFLARE_API_TOKEN` build
variable (Workers Scripts: Edit) under Settings → Builds → Variables and Secrets.

> The token lives in **CI only — never in the Worker**. A Worker can't set its own
> Secret at runtime (Secrets are deploy-time, read-only bindings; setting one is a
> privileged API call). Doing it from the build keeps that privilege in CI.

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
