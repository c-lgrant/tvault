// Registration / bind flow (registration.py). Generates one-time codes, serves
// a minimal bind page, and exchanges a code for the HMAC secret.
//
// /v1/exchange returns { hmacSecret(b64), webhookId, version, capabilities }.
// TV then verifies sha256(decoded hmacSecret) against the hmac_hash carried in
// the register URL (vault.py:257-263), so the secret + its published hash must
// be consistent — both come from the SecretProvider here.
//
// One-time codes are persisted via ctx.storage (D1 on Workers, fs on Node) —
// NOT an in-memory map. The bind→exchange pair is human-in-the-loop:
// the operator opens /bind on one request and TV calls /v1/exchange on a later,
// separate request. On Workers those land on different isolates, so an in-memory
// code is invisible to the exchange and TV reports "code expired or already
// used". A durable store fixes that — any isolate can consume the code.

import { base64Encode, constantTimeEqual, sha256Hex, utf8 } from "../core/crypto/encoding.ts";
import { forbidden, invalidRequest } from "../core/protocol/errors.ts";
import { WEBHOOK_VERSION } from "../core/protocol/types.ts";
import { readJsonBody } from "../core/middleware/body.ts";
import { sendError } from "../core/middleware/respond.ts";
import { isBound, markBound } from "./bindState.ts";
import { BIND_CODES_COLLECTION } from "../runtime/context.ts";
import type { RuntimeContext, StorageAdapter, WebhookConfig } from "../runtime/context.ts";
import type { FeatureModule } from "../core/registry.ts";
import type { Context } from "hono";
import type { AppEnv } from "../core/app.ts";

const CODE_TTL_MS = 300_000;

// Guard: once a webhook is bound, setup endpoints require the admin secret.
// If TV_ADMIN_SECRET is unset, the webhook is fully sealed after first bind —
// that is the intended safe default. Returns a 403 Response on failure or null
// when the caller is permitted to proceed.
async function guardBound(
  c: Context<AppEnv>,
  ctx: RuntimeContext,
): Promise<Response | null> {
  if (await isBound(ctx.storage)) {
    const provided = c.req.header("x-tv-admin-secret") ?? "";
    const expected = ctx.config.adminSecret ?? "";
    // If no admin secret is configured, deny outright (fully sealed). Otherwise
    // compare SHA-256 digests rather than the raw strings: constantTimeEqual
    // short-circuits on a length mismatch, which would leak the admin secret's
    // length for an arbitrary-length TV_ADMIN_SECRET. Hashing both sides first
    // makes every comparison operate on fixed-length (64-char) digests.
    const matches = !!expected
      && constantTimeEqual(await sha256Hex(provided), await sha256Hex(expected));
    if (!matches) {
      // Distinguish the two sealed states so the message isn't misleading: with
      // no TV_ADMIN_SECRET configured the webhook is permanently sealed (no
      // header can re-open it) and the operator must set the secret and redeploy.
      const message = expected
        ? "Webhook already bound. Provide a valid x-tv-admin-secret header to re-bind."
        : "Webhook already bound and no admin secret is configured, so it is permanently sealed. Set TV_ADMIN_SECRET and redeploy to re-bind.";
      return sendError(c, forbidden(message));
    }
  }
  return null;
}
// Internal collection for one-time bind codes. Underscore-prefixed so it never
// collides with a real credential collection; TV never lists it. The name lives
// in context.ts and is registered in INTERNAL_COLLECTIONS so every storage
// adapter provisions it (the FS adapter rejects unprovisioned collections).
const CODE_COLLECTION = BIND_CODES_COLLECTION;

// Issue a one-time code into durable storage. (KV set has no native TTL, so the
// expiry is stored in the doc and enforced on consume; an abandoned code lingers
// harmlessly until consumed — negligible — and is ignored once expired.)
async function issueCode(storage: StorageAdapter): Promise<string> {
  const code = crypto.randomUUID();
  await storage.set(CODE_COLLECTION, code, { exp: Date.now() + CODE_TTL_MS });
  return code;
}

// Consume a code exactly once. Deletes on any hit (used OR expired) so stale
// entries are cleaned on access; returns true only if it existed and is unexpired.
async function consumeCode(storage: StorageAdapter, code: string): Promise<boolean> {
  const doc = await storage.get(CODE_COLLECTION, code);
  if (!doc) return false;
  await storage.delete(CODE_COLLECTION, code);
  return typeof doc.exp === "number" && doc.exp >= Date.now();
}

function resolveExternalUrl(c: Context<AppEnv>, config: WebhookConfig): string | null {
  if (config.externalUrl) return config.externalUrl;
  const host = c.req.header("x-forwarded-host") ?? c.req.header("host");
  const proto = c.req.header("x-forwarded-proto") ?? "https";
  return host ? `${proto}://${host}` : null;
}

// The Token Vault frontend to bind to. A `tv` query param lets the launching TV
// instance (dev, prod, or a self-host) point the webhook back at itself, so the
// frontend URL is not hard-coded per deployment. The param is constrained to an
// https origin (http only for localhost) and is SHOWN on the bind page, because
// whoever receives the redirect can exchange the one-time code for the HMAC
// secret — the operator must confirm the destination. No param → the configured
// TOKENVAULT_FRONTEND_URL (the trusted default).
function resolveFrontend(c: Context<AppEnv>, config: WebhookConfig): string {
  const tv = c.req.query("tv");
  if (tv) {
    try {
      const u = new URL(tv);
      const isLocalhost = u.hostname === "localhost" || u.hostname === "127.0.0.1";
      if (u.protocol === "https:" || (u.protocol === "http:" && isLocalhost)) {
        return `${u.protocol}//${u.host}`;
      }
    } catch {
      // malformed tv param → fall through to the configured default
    }
  }
  return config.tokenvaultFrontendUrl;
}

// Best-effort deep link into the Cloudflare dashboard for THIS worker's settings,
// where TV_WEBHOOK_SEED is set. The worker name is the first label of a
// `*.workers.dev` host; behind a custom domain we can't know it, so fall back to
// the Workers & Pages list. `:account` is a dashboard placeholder Cloudflare
// resolves to the signed-in account, so we don't need the account id.
function workerNameFromHost(externalUrl: string): string | null {
  try {
    const host = new URL(externalUrl).hostname;
    if (host.endsWith(".workers.dev")) {
      const label = host.split(".")[0];
      return label && label !== "workers" ? label : null;
    }
  } catch {
    /* malformed URL → no name */
  }
  return null;
}

function dashboardSettingsUrl(workerName: string | null): string {
  return workerName
    ? `https://dash.cloudflare.com/?to=/:account/workers/services/view/${workerName}/production/settings`
    : "https://dash.cloudflare.com/?to=/:account/workers-and-pages";
}

function buildRegUrl(frontend: string, code: string, externalUrl: string, hmacHash: string): string {
  const webhookUrlB64 = base64Encode(utf8(externalUrl));
  const qs = new URLSearchParams({ code, webhook_url: webhookUrlB64, hmac_hash: hmacHash });
  return `${frontend.replace(/\/$/, "")}/vault/webhook-bind?${qs.toString()}`;
}

const PAGE_HEAD = `<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Connect to Token Vault</title>
<style>
  body{font:16px system-ui,sans-serif;max-width:34rem;margin:3rem auto;padding:0 1.5rem;color:#0f172a;line-height:1.5}
  h1{font-size:1.4rem}
  h2{font-size:1.1rem}
  .btn{display:inline-block;margin-top:1.5rem;padding:.7rem 1.25rem;border-radius:.5rem;
       background:#059669;color:#fff;text-decoration:none;font-weight:600}
  button.btn{border:0;cursor:pointer;font:inherit}
  .btn.secondary{background:#475569}
  code{background:#f1f5f9;padding:.15rem .35rem;border-radius:.25rem;font-size:.85em}
  pre{background:#0f172a;color:#e2e8f0;padding:.9rem 1rem;border-radius:.5rem;overflow-x:auto;font-size:.85em}
  .dest{margin-top:1rem;padding:.75rem 1rem;border:1px solid #e2e8f0;border-radius:.5rem;background:#f8fafc}
  .warn{margin-top:1rem;padding:.75rem 1rem;border:1px solid #fcd34d;border-radius:.5rem;background:#fffbeb}
  .tip{margin-top:1rem;padding:.75rem 1rem;border:1px solid #bbf7d0;border-radius:.5rem;background:#f0fdf4}
  .muted{color:#475569;font-size:.9em}
  hr{margin:1.75rem 0;border:0;border-top:1px solid #e2e8f0}
  ol{padding-left:1.2rem}
</style>`;

const BIND_PAGE = (regUrl: string, externalUrl: string, frontend: string) => `<!doctype html>
<html lang="en"><head>${PAGE_HEAD}</head><body>
<h1>Connect this webhook to Token Vault</h1>
<p>This webhook holds your credentials. Click below to complete the secure key
exchange — your encryption key never leaves this server.</p>
<p>Webhook URL: <code>${externalUrl}</code></p>
<p class="dest">Binding to: <code>${frontend}</code><br>
Only continue if this is your own Token Vault instance — the site you continue to
receives a one-time code that completes the key exchange.</p>
<p class="muted">Seed source: Workers Secret (hardened) — HKDF-derived in memory, never persisted.</p>
<a class="btn" href="${regUrl}">Connect to Token Vault</a>
</body></html>`;

// Shown when no seed exists yet: the webhook can't derive its HMAC secret, so it
// can't bind. The seed is set as a Workers Secret (the deploy script auto-
// provisions it when the build token allows; otherwise set it by hand). The
// dashboard deep link + `--name` are derived from the worker's *.workers.dev
// host so the operator needn't know the worker name or be in the project dir.
const SETUP_PAGE = (externalUrl: string, workerName: string | null) => {
  const settingsUrl = dashboardSettingsUrl(workerName);
  const nameFlag = workerName ? ` --name ${workerName}` : "";
  return `<!doctype html>
<html lang="en"><head>${PAGE_HEAD}</head><body>
<h1>Setup required — set the seed</h1>
<p>This webhook (<code>${externalUrl}</code>) can't bind yet. It needs a single
root secret — <code>TV_WEBHOOK_SEED</code> — before it can derive its encryption
key and HMAC secret. Set it as a Workers Secret, then reload and the
<strong>Connect</strong> button appears.</p>
<div class="tip">The deploy script (<code>npm run deploy</code>) auto-provisions
this Secret on the first deploy when the build token has <strong>Workers Scripts:
Edit</strong> — so usually there's nothing to do here. Set it manually only if
that step was skipped.</div>
<h2>Set it as a Workers Secret</h2>
<p>An encrypted, write-only Secret — not readable at rest, not in your repo.</p>
<a class="btn secondary" href="${settingsUrl}" target="_blank" rel="noopener">Open this Worker's Settings →</a>
<ol>
<li>The button opens the dashboard${workerName ? " on this worker's <strong>Settings</strong>" : " — open <strong>Workers &amp; Pages</strong>, pick this worker, then <strong>Settings</strong>"} → <strong>Variables and Secrets</strong>.</li>
<li><strong>Add variable</strong>, type <strong>Secret</strong>, name <code>TV_WEBHOOK_SEED</code>.</li>
<li>Value: a fresh 32-byte hex (generate with <code>openssl rand -hex 32</code>). Save.</li>
</ol>
<p class="muted">Or via the CLI:</p>
<pre>openssl rand -hex 32 | npx wrangler secret put TV_WEBHOOK_SEED${nameFlag}</pre>
${workerName ? "" : `<p class="muted">Run from your project directory (where <code>wrangler.toml</code> lives), or add <code>--name &lt;worker-name&gt;</code>.</p>\n`}<div class="warn"><strong>Choose before you bind.</strong> The seed is the root
key: if you change it <em>after</em> binding, the HMAC secret changes, Token
Vault's pinned hash no longer matches, and every call fails until you re-bind.</div>
<p><a href="">Reload this page</a> once a seed is set.</p>
</body></html>`;
};

export function exchangeModule(): FeatureModule {
  return {
    name: "exchange",
    register(app, ctx, registry) {
      app.get("/v1/register-url", async (c) => {
        // Seal check FIRST: a bound webhook must return 403 before any config
        // resolution, so an unauthenticated caller can't probe config state
        // (e.g. a misconfig 400) through a sealed endpoint.
        const blocked = await guardBound(c, ctx);
        if (blocked) return blocked;
        const externalUrl = resolveExternalUrl(c, ctx.config);
        if (!externalUrl) {
          return sendError(
            c,
            invalidRequest("Could not determine external URL. Set EXTERNAL_URL."),
          );
        }
        const code = await issueCode(ctx.storage);
        const hash = await ctx.secrets.hmacSecretHash();
        return c.json({
          registrationUrl: buildRegUrl(resolveFrontend(c, ctx.config), code, externalUrl, hash),
          code,
          expiresIn: 300,
          webhookUrl: externalUrl,
        });
      });

      app.post("/v1/exchange", async (c) => {
        const blocked = await guardBound(c, ctx);
        if (blocked) return blocked;
        const body = readJsonBody(c);
        const code = typeof body.code === "string" ? body.code : "";
        if (!code) return sendError(c, invalidRequest("Missing 'code'"));
        if (!(await consumeCode(ctx.storage, code))) {
          return c.json(
            { error: "code_expired", message: "Registration code expired or not found" },
            410,
          );
        }
        // Resolve secrets BEFORE persisting bind-state: if the secrets provider
        // throws (missing seed / misconfigured), a failed exchange must not
        // permanently seal the setup endpoints. Bind only on a fully successful
        // exchange.
        const secret = await ctx.secrets.hmacSecret();
        const webhookId = await ctx.secrets.webhookId();
        await markBound(ctx.storage);
        return c.json({
          hmacSecret: base64Encode(secret),
          webhookId,
          version: WEBHOOK_VERSION,
          capabilities: registry.capabilities,
        });
      });

      app.get("/bind", async (c) => {
        // Seal check FIRST: a bound webhook stays sealed even if it later loses
        // its seed (misconfigured). Checking config before the seal would serve
        // the setup page to unauthenticated callers on a bound-but-broken webhook.
        const blocked = await guardBound(c, ctx);
        if (blocked) return blocked;
        const externalUrl = resolveExternalUrl(c, ctx.config);
        if (!externalUrl) {
          return c.html("<h1>Webhook misconfigured</h1><p>EXTERNAL_URL is not set.</p>", 500);
        }
        // No seed yet → explain how to set the TV_WEBHOOK_SEED Secret instead of
        // failing opaquely.
        if (!(await ctx.secrets.isConfigured())) {
          return c.html(SETUP_PAGE(externalUrl, workerNameFromHost(externalUrl)), 503);
        }
        const frontend = resolveFrontend(c, ctx.config);
        const code = await issueCode(ctx.storage);
        const hash = await ctx.secrets.hmacSecretHash();
        const regUrl = buildRegUrl(frontend, code, externalUrl, hash);
        return c.html(BIND_PAGE(regUrl, externalUrl, frontend));
      });
    },
  };
}
