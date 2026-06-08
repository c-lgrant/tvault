// Registration / bind flow (registration.py). Generates one-time codes, serves
// a minimal bind page, and exchanges a code for the HMAC secret.
//
// /v1/exchange returns { hmacSecret(b64), webhookId, version, capabilities }.
// TV then verifies sha256(decoded hmacSecret) against the hmac_hash carried in
// the register URL (vault.py:257-263), so the secret + its published hash must
// be consistent — both come from the SecretProvider here.
//
// One-time codes are persisted via ctx.storage (KV on Workers, D1 if bound, fs
// on Node) — NOT an in-memory map. The bind→exchange pair is human-in-the-loop:
// the operator opens /bind on one request and TV calls /v1/exchange on a later,
// separate request. On Workers those land on different isolates, so an in-memory
// code is invisible to the exchange and TV reports "code expired or already
// used". A durable store fixes that — any isolate can consume the code.

import { base64Encode, utf8 } from "../core/crypto/encoding.ts";
import { invalidRequest } from "../core/protocol/errors.ts";
import { WEBHOOK_VERSION } from "../core/protocol/types.ts";
import { readJsonBody } from "../core/middleware/body.ts";
import { sendError } from "../core/middleware/respond.ts";
import type { StorageAdapter, WebhookConfig } from "../runtime/context.ts";
import type { FeatureModule } from "../core/registry.ts";
import type { Context } from "hono";
import type { AppEnv } from "../core/app.ts";

const CODE_TTL_MS = 300_000;
// Internal collection for one-time bind codes. Underscore-prefixed so it never
// collides with a real credential collection; TV never lists it.
const CODE_COLLECTION = "_bind_codes";

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
  code{background:#f1f5f9;padding:.15rem .35rem;border-radius:.25rem;font-size:.85em}
  pre{background:#0f172a;color:#e2e8f0;padding:.9rem 1rem;border-radius:.5rem;overflow-x:auto;font-size:.85em}
  .dest{margin-top:1rem;padding:.75rem 1rem;border:1px solid #e2e8f0;border-radius:.5rem;background:#f8fafc}
  .warn{margin-top:1rem;padding:.75rem 1rem;border:1px solid #fcd34d;border-radius:.5rem;background:#fffbeb}
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
<a class="btn" href="${regUrl}">Connect to Token Vault</a>
</body></html>`;

// Shown when the seed isn't set yet: the webhook can't derive its HMAC secret, so
// binding is impossible until the operator provisions TV_WEBHOOK_SEED.
const SETUP_PAGE = (externalUrl: string) => `<!doctype html>
<html lang="en"><head>${PAGE_HEAD}</head><body>
<h1>Setup required — set the seed secret</h1>
<p>This webhook (<code>${externalUrl}</code>) can't bind yet. It needs a single
secret, <code>TV_WEBHOOK_SEED</code>, before it can derive its encryption key and
HMAC secret. Nothing else needs storing — the keys are derived from this seed in
memory and never persisted.</p>
<div class="warn">
<strong>Set it as a Secret, not a plaintext variable.</strong> The seed is the
root key — keep it write-only and out of your repo.
</div>
<h2>Option A — Dashboard</h2>
<ol>
<li>Workers &amp; Pages → this worker → <strong>Settings → Variables and Secrets</strong>.</li>
<li><strong>Add variable</strong>, type <strong>Secret</strong>, name <code>TV_WEBHOOK_SEED</code>.</li>
<li>Value: a fresh 32-byte hex (generate with <code>openssl rand -hex 32</code>). Save.</li>
</ol>
<h2>Option B — CLI</h2>
<pre>openssl rand -hex 32 | npx wrangler secret put TV_WEBHOOK_SEED</pre>
<p>Then <a href="">reload this page</a> and the Connect button will appear.</p>
</body></html>`;

export function exchangeModule(): FeatureModule {
  return {
    name: "exchange",
    register(app, ctx, registry) {
      app.get("/v1/register-url", async (c) => {
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
        const body = readJsonBody(c);
        const code = typeof body.code === "string" ? body.code : "";
        if (!code) return sendError(c, invalidRequest("Missing 'code'"));
        if (!(await consumeCode(ctx.storage, code))) {
          return c.json(
            { error: "code_expired", message: "Registration code expired or not found" },
            410,
          );
        }
        const secret = await ctx.secrets.hmacSecret();
        return c.json({
          hmacSecret: base64Encode(secret),
          webhookId: await ctx.secrets.webhookId(),
          version: WEBHOOK_VERSION,
          capabilities: registry.capabilities,
        });
      });

      app.get("/bind", async (c) => {
        const externalUrl = resolveExternalUrl(c, ctx.config);
        if (!externalUrl) {
          return c.html("<h1>Webhook misconfigured</h1><p>EXTERNAL_URL is not set.</p>", 500);
        }
        // No seed yet → explain how to provision it instead of failing opaquely.
        if (!(await ctx.secrets.isConfigured())) {
          return c.html(SETUP_PAGE(externalUrl), 503);
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
