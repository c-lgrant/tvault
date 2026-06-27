# Deploy & Bind the Token Vault Webhook on Cloudflare Workers — End-to-End

This walks you from zero to a **bound, working** Token Vault webhook running on
Cloudflare Workers, using the one-click **Deploy to Workers** button.

The webhook is Token Vault's **data plane** — the credential custodian. It holds
(and optionally encrypts) the credentials and makes the upstream API calls. Token
Vault (the control plane) holds identities, grants, and policies but **never sees
your credential plaintext**. AES-256 encryption keys and the HMAC signing secret
are HKDF-derived in memory from a single seed you set as a Workers Secret; nothing
secret is ever written to disk or to Token Vault.

```
Agent ──▶ Token Vault (control plane)         You deploy THIS:
            • validates API key + policies      Cloudflare Worker (data plane)
            • signs a short-lived ticket    ──▶   • holds credentials (in D1)
            • 307-redirects to the webhook        • returns them to the agent
                                                   • makes upstream API calls
```

The Worker needs exactly **one provisioned resource** — a **D1 database** — and
one **Secret** (the seed). Replay protection uses the per-colo Cache API, so
there's no KV namespace to create.

---

## What you need

- A **Cloudflare account** (free tier is fine).
- A **Token Vault instance** to bind to. This tutorial uses the **dev** instance
  `https://tokenvault.one`. (For production it would be `https://tokenvault.uk`.)
- ~10 minutes. No local tooling required for the button path; the optional CLI
  path needs Node 18+.

> **Heads-up about the frontend URL.** The template ships with
> `TOKENVAULT_FRONTEND_URL = https://tokenvault.uk` (production). To bind to
> **dev**, either pass `?tv=https://tokenvault.one` on the bind link (Step 3 — the
> onboarding screen does this for you) **or** override the variable on the worker
> (Step 2b). Don't skip this, or your one-time code goes to the wrong Token Vault.

---

## Step 1 — Deploy the worker (the button)

1. Open the Token Vault webhook onboarding screen (on **tokenvault.one**), or use
   the **Deploy to Workers** button in the webhook example's README. Cloudflare
   forks the repo into your account, connects it to **Workers Builds** (so every
   later `git push` redeploys), and opens the setup wizard.

2. **Create the private Git repo** when prompted — this is the copy Cloudflare
   builds from.

3. **D1 is provisioned for you.** The template declares the `DB` binding with its
   `database_id` **omitted**, so the deploy auto-provisions a D1 database named
   `tv-webhook` and links it to the worker. On every later push the **same**
   database is reused — no data loss, nothing to pick or name. The storage table
   self-creates on first use; nothing to migrate.

4. **Variables.** You can leave these for now. `TOKENVAULT_FRONTEND_URL` defaults
   to production — we handle dev in Step 2/3.

5. Click **Deploy**. When it finishes you get a URL like:
   ```
   https://tv-webhook.<your-subdomain>.workers.dev
   ```
   Copy it. That's your webhook base URL for the rest of the tutorial.

> The "Deploy to Workers" version pulls the `webhook-ts-core` branch when launched
> from the dev onboarding screen, so you're testing the in-development webhook
> against dev — production stays on `main`.

---

## Step 2 — Provide the seed (usually automatic)

The webhook **cannot bind** until it has a root **seed** — the value the AES key +
HMAC secret are HKDF-derived from. It's set as a single **Workers Secret**,
`TV_WEBHOOK_SEED`.

### The default: auto-provisioned at deploy (zero-touch)

The repo's `deploy` script (`npm run deploy` → `scripts/deploy.sh`) deploys and
then mints `TV_WEBHOOK_SEED` as a Secret **only if one isn't already set**
(idempotent — never rotated on later pushes). Workers Builds runs your `deploy`
script automatically, so on most deploys the seed is already a Secret before the
webhook is even reachable and you can skip straight to Step 3.

This needs the build's wrangler token to have **Workers Scripts: Edit**. To
guarantee it, add a `CLOUDFLARE_API_TOKEN` build variable with that scope under
Settings → Builds → Variables and Secrets. The token lives in **CI, never in the
Worker** — a Worker can't set its own Secret at runtime.

### If it was skipped — set it by hand

Open your webhook's `/bind` page; with no seed it shows a setup screen that
deep-links to the right settings and prints the exact CLI command.

**Dashboard:**
1. Workers & Pages → your worker → **Settings** → **Variables and Secrets**.
2. **Add variable** → Type **Secret** → Name `TV_WEBHOOK_SEED`.
3. Value: a fresh 32-byte hex (`openssl rand -hex 32`). **Save** — no redeploy.

**CLI** (the setup page bakes in `--name` so it works from any directory):
```bash
openssl rand -hex 32 | npx wrangler secret put TV_WEBHOOK_SEED --name <worker>
```

> ⚠️ **Settle the seed before you bind.** The seed is the root key: change it
> *after* binding and the HMAC secret changes, Token Vault's pinned
> `sha256(hmacSecret)` no longer matches, and every call fails until you
> **re-bind**.

**Optional — `OAUTH_PROVIDERS_JSON`** (only if you want the webhook to refresh
OAuth tokens autonomously). Same place, as a Secret, value is a JSON map:
```json
{ "google": { "clientId": "…", "clientSecret": "…" } }
```

---

## Step 2b — Point the webhook at the right Token Vault

The webhook redirects the one-time bind code to a Token Vault frontend. Pick one:

**Per-bind (recommended for testing).** Do nothing here; pass
`?tv=https://tokenvault.one` on the bind link in Step 3. The onboarding screen
appends it automatically. The webhook validates it (https origin only; http
allowed for localhost) and shows the destination on the bind page to confirm.

**Pin it on the worker (set-and-forget for a dedicated dev webhook).** Settings →
Variables and Secrets → add a **plaintext** variable
`TOKENVAULT_FRONTEND_URL = https://tokenvault.one`. Now plain `/bind` redirects to
dev.

---

## Step 3 — Bind to Token Vault

This is the pairing handshake. It runs **server-to-server** — Token Vault's
backend calls your webhook directly — so browser CORS warnings on the onboarding
screen are expected and don't block anything.

1. Open the bind URL:
   ```
   https://tv-webhook.<your-subdomain>.workers.dev/bind?tv=https://tokenvault.one
   ```
   (or just `/bind` if you pinned the variable in Step 2b, or click the bind link
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

## Step 4 — Verify it actually works

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
| Onboarding: **"Can't verify from browser (CORS), but URL looks valid"** | Expected. The browser can't read the webhook cross-origin; binding is server-to-server. Proceed. |
| Bind page shows **`tokenvault.uk`** (prod) instead of dev | The `?tv=` param is missing/ignored. Use `/bind?tv=https://tokenvault.one`, or set `TOKENVAULT_FRONTEND_URL` (Step 2b). |
| Bind page says **"Setup required"** | No seed yet (Step 2). The deploy auto-provision was skipped — set `TV_WEBHOOK_SEED` as a Secret (the page shows the exact command), then reload. |
| `wrangler secret put` → **"Required Worker name missing"** | You ran it outside the project dir. Add `--name <worker>` (the setup page shows the exact command), or `cd` into the repo. |
| Bind fails with an **HMAC hash mismatch** | The seed changed between the register-URL and the exchange. Settle the seed first, then bind. |
| Deploy fails referencing a **D1 database that doesn't exist** | Don't add a placeholder `database_id` to `wrangler.toml` — a non-empty id disables auto-provisioning. Leave it omitted (the binding has only `binding` + `database_name`). |
| Agent credential request returns **403 POLICY_DENIED** | A policy (IP allowlist, time window, rate limit, …) blocked it — that's Token Vault working, not the webhook. Check the agent's attached policies. |
| Credential request **denied at the webhook by IP** | The webhook denies Token Vault's own egress IP on `/v1/credential` etc. (defense-in-depth). That path is for the *agent*, not TV. If you set `TOKENVAULT_IP`/`DENY_IPS`, make sure they only list TV, not your agent. |

---

## Optional configuration

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

1. **Deploy** with the button → D1 auto-provisioned (reused on every push), get
   the `*.workers.dev` URL.
2. **Seed** — auto-provisioned as a `TV_WEBHOOK_SEED` Secret at deploy (or set it
   by hand); required before bind.
3. **Target the right Token Vault** (dev via `?tv=` or the pinned variable).
4. **Bind** at `/bind` — confirm the destination, let the server-to-server
   exchange complete.
5. **Verify** with a stored credential + an agent fetch.

Your credentials live only in your Cloudflare account; Token Vault stays the
policy plane and never holds the plaintext.

---

## Keeping it up to date

To upgrade later, run the **Update webhook** Action in your repo (Actions tab) →
review the PR → merge. Workers Builds redeploys against the same D1 and seed.
Full details: [UPGRADING.md](./UPGRADING.md).
