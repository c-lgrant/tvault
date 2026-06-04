// Registration / bind flow (registration.py). Generates one-time codes, serves
// a minimal bind page, and exchanges a code for the HMAC secret.
//
// /v1/exchange returns { hmacSecret(b64), webhookId, version, capabilities }.
// TV then verifies sha256(decoded hmacSecret) against the hmac_hash carried in
// the register URL (vault.py:257-263), so the secret + its published hash must
// be consistent — both come from the SecretProvider here.
//
// Codes are kept in an in-memory TTL map. For the Node container this is exactly
// right. On Workers the bind→exchange pair normally lands in one isolate during
// the post-deploy bootstrap; if a code is missed, TV retries.
// TODO(worker): back registration codes with KV for multi-isolate robustness.

import { base64Encode, utf8 } from "../core/crypto/encoding.ts";
import { invalidRequest } from "../core/protocol/errors.ts";
import { WEBHOOK_VERSION } from "../core/protocol/types.ts";
import { readJsonBody } from "../core/middleware/body.ts";
import { sendError } from "../core/middleware/respond.ts";
import type { WebhookConfig } from "../runtime/context.ts";
import type { FeatureModule } from "../core/registry.ts";
import type { Context } from "hono";
import type { AppEnv } from "../core/app.ts";

const CODE_TTL_MS = 300_000;

function resolveExternalUrl(c: Context<AppEnv>, config: WebhookConfig): string | null {
  if (config.externalUrl) return config.externalUrl;
  const host = c.req.header("x-forwarded-host") ?? c.req.header("host");
  const proto = c.req.header("x-forwarded-proto") ?? "https";
  return host ? `${proto}://${host}` : null;
}

function buildRegUrl(frontend: string, code: string, externalUrl: string, hmacHash: string): string {
  const webhookUrlB64 = base64Encode(utf8(externalUrl));
  const qs = new URLSearchParams({ code, webhook_url: webhookUrlB64, hmac_hash: hmacHash });
  return `${frontend.replace(/\/$/, "")}/vault/webhook-bind?${qs.toString()}`;
}

const BIND_PAGE = (regUrl: string, externalUrl: string) => `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Connect to Token Vault</title>
<style>
  body{font:16px system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1.5rem;color:#0f172a}
  .btn{display:inline-block;margin-top:1.5rem;padding:.7rem 1.25rem;border-radius:.5rem;
       background:#059669;color:#fff;text-decoration:none;font-weight:600}
  code{background:#f1f5f9;padding:.15rem .35rem;border-radius:.25rem;font-size:.85em}
</style></head><body>
<h1>Connect this webhook to Token Vault</h1>
<p>This webhook holds your credentials. Click below to complete the secure key
exchange — your encryption key never leaves this server.</p>
<p>Webhook URL: <code>${externalUrl}</code></p>
<a class="btn" href="${regUrl}">Connect to Token Vault</a>
</body></html>`;

export function exchangeModule(): FeatureModule {
  // code -> expiry epoch ms
  const codes = new Map<string, number>();

  const issueCode = (): string => {
    const code = crypto.randomUUID();
    codes.set(code, Date.now() + CODE_TTL_MS);
    return code;
  };

  const consumeCode = (code: string): boolean => {
    const expiry = codes.get(code);
    if (expiry === undefined || expiry < Date.now()) return false;
    codes.delete(code); // one-time use
    return true;
  };

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
        const code = issueCode();
        const hash = await ctx.secrets.hmacSecretHash();
        return c.json({
          registrationUrl: buildRegUrl(ctx.config.tokenvaultFrontendUrl, code, externalUrl, hash),
          code,
          expiresIn: 300,
          webhookUrl: externalUrl,
        });
      });

      app.post("/v1/exchange", async (c) => {
        const body = readJsonBody(c);
        const code = typeof body.code === "string" ? body.code : "";
        if (!code) return sendError(c, invalidRequest("Missing 'code'"));
        if (!consumeCode(code)) {
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
        const code = issueCode();
        const hash = await ctx.secrets.hmacSecretHash();
        const regUrl = buildRegUrl(ctx.config.tokenvaultFrontendUrl, code, externalUrl, hash);
        return c.html(BIND_PAGE(regUrl, externalUrl));
      });
    },
  };
}
