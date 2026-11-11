# Token Vault Webhook — TS/Hono

A deployment-agnostic, multi-runtime Token Vault webhook server (the credential
**data plane**) built with [Hono](https://hono.dev). One runtime-neutral core,
two runtimes:

- **Node + ngrok** — container with an ngrok tunnel for rapid self-hosting
- **Node + Cloudflare Tunnel** — container with a cloudflared tunnel (no open ports)
- **Cloudflare Workers** — edge runtime, zero infra

Token Vault holds policy and identity; **this webhook holds the credentials**.
The control plane never sees your encryption key. This is the maintained
reference; the Python example in [`../webhook-ngrok/`](../webhook-ngrok/) is
legacy and does not implement the current spec.

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
    replay/         # memory (Node) | stored (Workers nonces, D1) + cache (Workers request ids)
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
persisted. Credentials and used ticket nonces live in **D1**; request-id replay
protection uses the per-colo **Cache API** (no binding). The one-click button auto-provisions the D1 database
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
`clientId`) in its meta, so the webhook can refresh it with the same
`OAUTH_PROVIDERS_JSON` entry.

### Refresh

Refresh is the webhook's job; Token Vault never schedules it. A token with an
`oauth` hint is refreshed:

- **on a schedule**: a Workers cron trigger (`[triggers]` in `wrangler.toml`,
  every 10 minutes) or, on Node, a timer (`OAUTH_REFRESH_INTERVAL_SECONDS`, default
  600, `0` turns it off) renews every such token expiring within
  `OAUTH_REFRESH_WINDOW_SECONDS` (default 1200);
- **when you press Refresh** in Token Vault (`POST /v1/refresh-notify`);
- **at fetch time**: `/v1/credential` and `/v1/proxy` refresh one that is
  already expired before using it. A token that is still valid but within a
  minute of expiry is served as it is and refreshed in the background (once per
  service per isolate). If a refresh fails the stored token is served as before.

An agent never receives the refresh token: `/v1/credential` removes it from an
`agent_credential` response, so stopping an agent's access also stops any
renewals. A person's own reveal (`user_reveal`) still shows it.

A refresh keeps all of the token's metadata (including `creationId`), stores a
rotated refresh token when the provider returns one and keeps the old one when it
does not, and stamps `expiryTime`, `updatedAt` and `lastRefreshed`. A failure
leaves the credential untouched and records only `refreshError` (the provider's
short OAuth error code, such as `invalid_grant`, or `provider_unreachable`),
`refreshFailedAt` and `refreshReconnect` in meta. `refreshReconnect: true`
(`invalid_grant`, GitHub's `bad_refresh_token`) means only a new consent fixes it:
the schedule skips that token until you reconnect it or a manual Refresh
succeeds. `/v1/refresh-notify` answers such a failure with `status:
"refresh_failed"` plus `error` and `reconnectRequired`. Tokens without an `oauth`
hint (pasted, or minted with Token Vault's old built-in clients) are never
refreshed on the schedule.

Optional per-provider keys in `OAUTH_PROVIDERS_JSON`: `authorizeParams` (extra
authorize-URL parameters; they never replace the ones the webhook sets) and
`tokenAuthMethod` (`client_secret_post`, the default, or `client_secret_basic`,
the default for `spotify`).

Provider notes:

- **Google**: the webhook asks for `access_type=offline&prompt=consent`, without
  which Google issues no refresh token. Refresh answers omit `refresh_token`; the
  stored one stays valid. While the app's consent screen is in *Testing*, Google
  expires refresh tokens after 7 days; publish the app to avoid that.
- **GitHub**: an OAuth App issues non-expiring tokens with no refresh token, so
  there is nothing to refresh. A GitHub App with expiring user tokens issues
  8-hour tokens and a new refresh token on every refresh, which the webhook stores.
- **Spotify**: the client authenticates with HTTP Basic. A refresh may or may not
  return a new refresh token; both are handled. The state ticket is the usual
`base64url(json).hex_hmac` with `pur: "oauth_connect"` and the extra fields `prv`
(provider), `tku` (token URL, cross-checked), `clid` (client id), `rdu`
(redirect URI) and `scp` (space-separated scopes). It may also carry the store
constraints `mode` (`create` refuses an existing service with `already_exists`)
and `cid` (stored as `meta.creationId`), applied as `/v1/store` applies them.

## Legacy `tv-refresh` (opt-in)

`tv-refresh` is the legacy refresh path where the control plane refreshes tokens
minted with its own built-in OAuth apps. It is the only path that returns a
refresh token to the control plane, so it is **off by default**: the module is
not registered and `/v1/exchange` and `/v1/health` do not list the capability.
Webhook-owned refresh (`refresh`, `/v1/refresh-notify`) covers every other case.

To enable it, set `TV_REFRESH_ENABLED=true` (a Worker `[vars]` entry or a Node
environment variable; any other value leaves it off). After changing the switch,
press **Verify Connection** in the console so the capability list is re-read.

## Protocol notes

- **`/v1/proxy` streams.** The upstream response body is passed through as it
  arrives. The 30 s upstream timeout covers waiting for response headers only;
  slow headers return `upstream_timeout`. A stream that stays silent for 60 s
  (no bytes from the upstream) is aborted, so an SSE stream needs a keep-alive
  at least that often; one that keeps sending can stay open.
- **`Server-Timing` (optional response header on `/v1/proxy`).** Lets the control
  plane split webhook time from upstream time: `tv-wh;dur=<ms>` is time from the
  start of request handling to just before the upstream call, `tv-up;dur=<ms>` is
  the upstream call until its response headers arrived (the body streams after
  that and is not included). Milliseconds with one decimal; durations only. An
  upstream's own `Server-Timing` value is kept and ours is appended. The
  `upstream_timeout` and `upstream_error` responses carry `tv-wh` only. Clients
  that do not read the header can ignore it.
- **Audit retention (opt-in).** Audit events are kept forever by default. Set
  `AUDIT_RETENTION_DAYS` to a positive number to delete older events from the cron
  trigger (Workers) or an hourly timer (Node); unset or `0` keeps everything. A paginated `/v1/storage` list of
  `audit` (`options.limit`) is ordered and limited by the store itself.
- **`/v1/storage` never returns a credential document.** `get` on `tokens`
  answers with the same metadata `list` does: no `fields`, no ciphertext, no
  plaintext value of an old document.
- **`/v1/proxy` does not call private addresses.** An upstream on a loopback,
  private or link-local address, `localhost`, a single-label name or a name under
  `.local`, `.internal`, `.lan` or `.home.arpa` gets `403 upstream_not_allowed`.
  The Node runtime also resolves the name and checks every address. Set
  `TV_PROXY_ALLOW_PRIVATE=true` if your upstream is on your own network. The
  upstream call resolves the name again, so the connection is not pinned to the
  checked address. A `Host`, `Forwarded` or `X-Forwarded-Host` header is never
  sent upstream: a forwarded one is dropped, and a header template that sets one
  gets `400 invalid_request`.
- **Origin allowlist for `/v1/proxy` (opt-in).** The control plane names the
  upstream URL, and the webhook puts the credential into the request. To bind
  each credential to the origins you trust, set `TV_PROXY_ALLOWED_ORIGINS` to a
  JSON object of credential name → origins, for example
  `{"github":["https://api.githubcopilot.com"],"*":["https://mcp.example.com"]}`.
  `"*"` applies to every credential. When the variable is set, a credential with
  no matching entry is refused (`403 upstream_not_allowed`). When it is not set,
  any public origin is called. A value that is not valid stops the webhook at
  start: a list that cannot be read must not mean "allow all".
- **One-shot tickets on Workers are atomic.** Each ticket nonce is one
  insert-if-absent row in D1, so a ticket cannot be used twice in two colos. The
  cron trigger deletes expired rows. This costs one D1 row write per credential
  read, store and proxy call; on the D1 free plan (100,000 rows written per day)
  set `TV_REPLAY_NONCES="cache"` to go back to the per-colo cache if you get
  near that limit. Request ids stay in the cache.
- **PKCE verifier.** The OAuth connect flow derives its `code_verifier` from the
  webhook's own encryption key, not from the HMAC secret the control plane holds.

## Tests

```bash
npm run typecheck       # tsc --noEmit
npm test                # vitest: conformance + modules + security
sh test/smoke/run.sh    # local Node HTTP E2E round-trip
```

## Upgrading

### Upgrading from 0.13 or earlier

The legacy `tv-refresh` capability is now opt-in (see
[Legacy `tv-refresh` (opt-in)](#legacy-tv-refresh-opt-in)). After upgrading,
tokens connected through Token Vault's own Google, GitHub or Spotify apps stop
refreshing unless you set `TV_REFRESH_ENABLED=true` (a Worker `[vars]` entry or a
Node environment variable). Then press **Verify Connection** in the Token Vault
settings so the capability list is re-read. Tokens connected through your own
OAuth app (`OAUTH_PROVIDERS_JSON`) are unaffected.

### Redeploy

Upgrades are an in-place redeploy — no migration, no re-keying, no URL change.
Run the **Update webhook** GitHub Action in your repo to open a PR, merge it, and
Workers Builds redeploys against your existing D1 + seed. See
[deploy/cloudflare/UPGRADING.md](deploy/cloudflare/UPGRADING.md).

## License

[MIT](../../LICENSE) — Token Vault project.
