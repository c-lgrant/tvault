# Deploy & Bind the Token Vault Webhook on Cloudflare Workers — End-to-End

This walks you from zero to a **bound, working** Token Vault webhook running on
Cloudflare Workers, using the one-click **Deploy to Workers** button.

The webhook is Token Vault's **data plane** — the credential custodian. It holds
(and optionally encrypts) the credentials and makes the upstream API calls. Token
Vault (the control plane) holds identities, grants, and policies but **never sees
your credential plaintext**. AES-256 encryption keys and the HMAC signing secret
are HKDF-derived in memory from a single seed you set after deploy; nothing
secret is ever written to disk or to Token Vault.

```
Agent ──▶ Token Vault (control plane)         You deploy THIS:
            • validates API key + policies      Cloudflare Worker (data plane)
            • signs a short-lived ticket    ──▶   • holds credentials (in KV/D1)
            • 307-redirects to the webhook        • returns them to the agent
                                                   • makes upstream API calls
```

---

## What you need

- A **Cloudflare account** (free tier is fine).
- A **Token Vault instance** to bind to. This tutorial uses the **dev** instance
  `https://tokenvault.one`. (For production it would be `https://tokenvault.uk`.)
- ~10 minutes. No local tooling required for the button path; the optional CLI
  path needs Node 18+.

> **Heads-up about the frontend URL.** The template ships with
> `TOKENVAULT_FRONTEND_URL = https://tokenvault.uk` (production). To bind to
> **dev**, you must either pass `?tv=https://tokenvault.one` on the bind link
> (Step 4 — the onboarding screen does this for you) **or** override the variable
> on the worker (Step 3b). Don't skip this, or your one-time code gets sent to the
> wrong Token Vault.

---

## Step 1 — Deploy the worker (the button)

1. Open the Token Vault webhook onboarding screen (on **tokenvault.one**), or use
   the **Deploy to Workers** button in the webhook example's README. Cloudflare
   forks the repo into your account and opens the setup wizard.

2. **Create the private Git repo** when prompted — this is the copy Cloudflare
   builds from.

3. **Select KV namespace.** The template declares one KV namespace (binding `KV`)
   that backs **replay protection** (request IDs + ticket nonces). The wizard
   shows one KV step:
   - **First time:** choose **Create new**. Cloudflare provisions one namespace and
     writes its id into your deployed config.
   - **Re-deploying, or a leftover `tv-webhook` namespace already exists** (e.g.
     from an earlier failed attempt): choose the **existing** namespace instead of
     "Create new". The wizard names new namespaces after the worker (`tv-webhook`),
     so creating a second one with the same name fails with *"already exists"*.
     Selecting the existing one avoids that. (Tip: delete stale `tv-webhook`
     namespaces under **Workers & Pages → KV** for a clean slate.)

4. **Create D1 database.** The template declares a `DB` binding (D1) for
   **credential storage**. The wizard shows a **"Create D1 database"** step — same
   pattern: **Create new** the first time, or pick the **existing** `tv-webhook`
   db when re-deploying. (A KV namespace and a D1 db can share the name
   `tv-webhook` without colliding — different resource types.) The storage table
   self-creates on first use; nothing to migrate.

5. **Variables.** You can leave these for now. `TOKENVAULT_FRONTEND_URL` defaults
   to production — we handle dev in Step 3/4.

6. Click **Deploy**. When it finishes you get a URL like:
   ```
   https://tv-webhook.<your-subdomain>.workers.dev
   ```
   Copy it. That's your webhook base URL for the rest of the tutorial.

> The "Deploy to Workers" version pulls the `webhook-ts-core` branch when launched
> from the dev onboarding screen, so you're testing the in-development webhook
> against dev — production stays on `main`.

---

## Step 2 — Provide the seed

The webhook **cannot bind** until it has a root **seed** — the value the AES key
+ HMAC secret are HKDF-derived from. Open your webhook's `/bind` page; with no
seed set it shows a setup screen with two paths. Pick **one**.

### Option 1 — Generate & save (one-click, good for dev)

Click **Generate & save seed** on the setup page. The webhook mints a random
32-byte seed and stores it in **KV** (key `seed:v1`). Reload and the **Connect**
button appears — no CLI, no redeploy.

> ⚠️ The seed is stored in KV, **readable to anyone with access to your KV
> namespace**. Your *credentials* live in D1, so a leak of one store alone can't
> decrypt — but for production prefer Option 2 (or auto-provision as a Secret at
> deploy — see Step 2c).

### Option 2 — Workers Secret (hardened, recommended for production)

Set `TV_WEBHOOK_SEED` as an encrypted, write-only **Secret** (not readable at
rest). The setup page deep-links straight to the right settings screen.

**Dashboard:**
1. Workers & Pages → your worker → **Settings** → **Variables and Secrets**.
2. **Add variable** → Type **Secret** → Name `TV_WEBHOOK_SEED`.
3. Value: a fresh 32-byte hex (`openssl rand -hex 32`). **Save** — no redeploy.

**CLI** (the setup page bakes in `--name` so it works from any directory):
```bash
openssl rand -hex 32 | npx wrangler secret put TV_WEBHOOK_SEED --name <worker>
```

A `TV_WEBHOOK_SEED` Secret **always takes precedence** over a generated seed.

> ⚠️ **Choose before you bind.** The seed is the root key: change it *after*
> binding and the HMAC secret changes, Token Vault's pinned `sha256(hmacSecret)`
> no longer matches, and every call fails until you **re-bind**. To move Option 1
> → Option 2 without re-binding, set the Secret to the **same** value (copy it
> from Workers & Pages → KV → `seed:v1`); the generated copy is then ignored.

### Option 3 (Step 2c) — Auto-provision the seed as a Secret at deploy

The hardened custody of Option 2 with the zero-touch convenience of Option 1: the
deploy provisions the Secret for you. Set the Workers Builds **deploy command**
(Settings → Builds) to:

```bash
sh scripts/deploy.sh
```

It deploys, then runs `scripts/ensure-seed.sh`, which generates `TV_WEBHOOK_SEED`
and stores it as a Secret **only if one isn't already set** (idempotent — safe to
re-run on every push). `wrangler secret put` needs **Workers Scripts: Edit**; if
it fails on auth, add a `CLOUDFLARE_API_TOKEN` build variable with that scope. The
token lives in **CI, never in the Worker** — a Worker can't set its own Secret at
runtime. With this, the webhook already has its seed by the time it's reachable,
so you can skip the `/bind` generate button.

**Optional — `OAUTH_PROVIDERS_JSON`** (only if you want the webhook to refresh
OAuth tokens autonomously). Same place, as a Secret, value is a JSON map:
```json
{ "google": { "clientId": "…", "clientSecret": "…" } }
```

---

## Step 3 — Point the webhook at the right Token Vault

The webhook redirects the one-time bind code to a Token Vault frontend. Pick one:

**3a — Per-bind (recommended for testing).** Do nothing here; pass
`?tv=https://tokenvault.one` on the bind link in Step 4. The onboarding screen
appends this automatically. The webhook validates it (https origin only; http
allowed for localhost) and shows the destination on the bind page for you to
confirm.

**3b — Pin it on the worker (set-and-forget for a dedicated dev webhook).**
Settings → Variables and Secrets → add a **plaintext** variable
`TOKENVAULT_FRONTEND_URL = https://tokenvault.one`. Now plain `/bind` (no query
param) redirects to dev.

---

## Step 4 — Bind to Token Vault

This is the pairing handshake. It runs **server-to-server** — Token Vault's
backend calls your webhook directly — so browser CORS warnings on the onboarding
screen are expected and don't block anything.

1. Open the bind URL:
   ```
   https://tv-webhook.<your-subdomain>.workers.dev/bind?tv=https://tokenvault.one
   ```
   (or just `/bind` if you pinned the variable in Step 3b, or click the bind link
   on the onboarding screen).

2. The bind page shows **"Binding to: `https://tokenvault.one`"**. **Confirm it
   says `tokenvault.one`, not `tokenvault.uk`** before continuing. (Whoever
   receives this code can exchange it for the HMAC secret, so this confirmation is
   your anti-phishing check.)

3. Continue. The webhook mints a one-time code and redirects to
   `https://tokenvault.one/vault/webhook-bind?code=…`.

4. Token Vault's backend calls your webhook's `POST /v1/exchange`, retrieves the
   HMAC secret, and verifies `sha256(hmacSecret)` matches the hash the webhook
   advertised. On success the screen confirms the webhook is **paired**.

You now have a webhook-mode vault wired to dev.

---

## Step 5 — Verify it actually works

1. **Health (optional, from a terminal):**
   ```bash
   curl https://tv-webhook.<your-subdomain>.workers.dev/v1/health
   ```
   Returns `{ "status": "ok", … , "capabilities": [ … ] }`. The capability list
   reflects the mounted modules (`storage`, `credential`, `store`, `proxy`,
   `refresh`, …).

2. **Store a credential** in Token Vault (the UI writes it to your webhook via the
   `store` capability — it lands in your D1 database, encrypted, never on Token
   Vault).

3. **Create an agent**, grant it that token, and have it call:
   ```
   GET https://tokenvault.one/api/agents/credentials?service=<name>
   ```
   with its `tvagent_…` key. Token Vault validates the key + policies, then
   **307-redirects** the agent to your webhook's `/v1/credential` with a signed
   ticket; your webhook returns the credential straight to the agent. Token Vault
   never touches the bytes.

If the agent gets its credential, the full control-plane → data-plane round trip
is working.

---

## Troubleshooting

| Symptom | Cause & fix |
|---|---|
| Wizard: **"Cannot provision a KV Namespace … already exists"** | A `tv-webhook` KV namespace is left over from a prior attempt. In the KV step pick the **existing** namespace, or delete stale ones under Workers & Pages → KV, then retry. |
| Onboarding: **"Can't verify from browser (CORS), but URL looks valid"** | Expected. The browser can't read the webhook cross-origin; binding is server-to-server. Proceed. |
| Bind page shows **`tokenvault.uk`** (prod) instead of dev | The `?tv=` param is missing/ignored. Use `/bind?tv=https://tokenvault.one`, or set `TOKENVAULT_FRONTEND_URL` (Step 3b). |
| Bind page says **"Setup required"** | No seed yet (Step 2). Click **Generate & save**, or set `TV_WEBHOOK_SEED`, then reload. |
| `wrangler secret put` → **"Required Worker name missing"** | You ran it outside the project dir. Add `--name <worker>` (the setup page shows the exact command), or `cd` into the repo. |
| Bind fails with an **HMAC hash mismatch** | The seed changed between the register-URL and the exchange (e.g. you switched custody mid-flow, or regenerated). Settle the seed first, then bind. |
| Agent credential request returns **403 POLICY_DENIED** | A policy (IP allowlist, time window, rate limit, …) blocked it — that's Token Vault working, not the webhook. Check the agent's attached policies. |
| Credential request **denied at the webhook by IP** | The webhook denies Token Vault's own egress IP on `/v1/credential` etc. (defense-in-depth). That path is for the *agent*, not TV. If you set `TOKENVAULT_IP`/`DENY_IPS`, make sure they only list TV, not your agent. |

---

## Optional configuration

- **KV-only storage (drop D1)** — this template stores credentials in D1 by
  default. To store in KV instead, remove the `[[d1_databases]]` block from
  `wrangler.toml`; the runtime falls back to KV-only storage. (KV is required
  either way — replay protection always uses it.)
- **Logs & traces** — `[observability]` is enabled in `wrangler.toml`, so the
  worker persists structured logs + per-invocation traces. View them in
  **Workers & Pages → your worker → Logs**, or stream live with
  `wrangler tail --name <worker>`.
- **Custom domain** — if you front the worker with a domain that rewrites `Host`,
  set `WEBHOOK_EXTERNAL_URL` so generated URLs are correct.
- **Extra denylist entries** — `DENY_IPS` / `DENY_ORIGINS` (comma-separated) and
  `TOKENVAULT_IP` tighten the app-level denylist on credential/store/totp routes.

---

## Recap

1. **Deploy** with the button → one KV namespace (replay) + one D1 db (storage),
   get the `*.workers.dev` URL.
2. **Set `TV_WEBHOOK_SEED`** (Secret) — required before bind.
3. **Target the right Token Vault** (dev via `?tv=` or the pinned variable).
4. **Bind** at `/bind` — confirm the destination, let the server-to-server
   exchange complete.
5. **Verify** with a stored credential + an agent fetch.

Your credentials live only in your Cloudflare account; Token Vault stays the
policy plane and never holds the plaintext.
