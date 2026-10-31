// OAuth callback for "connect with your own app" (capability `oauth-callback`).
//
//   GET /v1/oauth/callback?code=…&state=<ticket>
//
// The user registered an OAuth app at the provider with this URL as its
// redirect URI. After consent the provider sends the browser here, so the
// authorization code goes straight to the webhook and never to the control
// plane. The webhook:
//   1. verifies the control-plane-signed state ticket (signature, 10 min expiry,
//      one-shot nonce) and that it names THIS callback URL;
//   2. exchanges the code at the token endpoint with the client secret from
//      LOCAL config (OAUTH_PROVIDERS_JSON) and the PKCE verifier derived from
//      the HMAC secret + nonce (the verifier never travelled via the browser);
//   3. stores the result as the named service in the standard encrypted token
//      document, with a non-secret `oauth` hint so /v1/refresh-notify works;
//   4. 302s the browser to the Token Vault frontend result page. The redirect
//      carries only a status, the service name and a short error code: never a
//      code, token or provider error text.
//
// The client secret is only ever sent to a token URL the operator configured or
// that is in the built-in table, regardless of what the ticket says.

import { denylist } from "../core/middleware/denylist.ts";
import { WebhookError } from "../core/protocol/errors.ts";
import {
  BUILTIN_TOKEN_URLS,
  derivePkceVerifier,
  OAUTH_CALLBACK_CAPABILITY,
  OAUTH_CALLBACK_PATH,
  OAUTH_CONNECT_PURPOSE,
  OAUTH_STATE_TTL_SECONDS,
} from "../core/protocol/oauthConnect.ts";
import { verifyTicket } from "../core/protocol/tickets.ts";
import { buildEncryptedTokenDocument } from "../core/protocol/tokendoc.ts";
import type { FeatureModule } from "../core/registry.ts";
import { resolveExternalUrl } from "./webhookLinks.ts";

const EXCHANGE_TIMEOUT_MS = 10_000;

function nowIso(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

/** A failure that is shown to the user as a short non-secret code. */
class ConnectFailure extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

export function oauthCallbackModule(): FeatureModule {
  return {
    name: "oauth-callback",
    capability: OAUTH_CALLBACK_CAPABILITY,
    register(app, ctx) {
      app.get(OAUTH_CALLBACK_PATH, denylist(ctx.config), async (c) => {
        const result = new URL("/tokens/oauth-result", ctx.config.tokenvaultFrontendUrl);
        const done = (params: Record<string, string>) => {
          for (const [k, v] of Object.entries(params)) result.searchParams.set(k, v);
          // 302 + no-store: the URL is single-use and must not be cached.
          return c.redirect(result.toString(), 302);
        };
        c.header("Cache-Control", "no-store");
        c.header("Referrer-Policy", "no-referrer");

        let service = "";
        try {
          if (!(await ctx.secrets.isConfigured())) throw new ConnectFailure("setup_required");

          const state = c.req.query("state") ?? "";
          const code = c.req.query("code") ?? "";
          const providerError = c.req.query("error");
          if (!state) throw new ConnectFailure("state_invalid");

          const secret = await ctx.secrets.hmacSecret();
          let payload;
          try {
            payload = await verifyTicket(state, secret, ctx.replay, OAUTH_STATE_TTL_SECONDS + 60);
          } catch (e) {
            if (e instanceof WebhookError && e.code === "ticket_expired") throw new ConnectFailure("state_expired");
            throw new ConnectFailure("state_invalid");
          }
          if (payload.pur !== OAUTH_CONNECT_PURPOSE) throw new ConnectFailure("state_invalid");

          service = typeof payload.svc === "string" ? payload.svc : "";
          const provider = typeof payload.prv === "string" ? payload.prv.toLowerCase() : "";
          if (!service || !provider) throw new ConnectFailure("state_invalid");
          result.searchParams.set("service", service);
          result.searchParams.set("provider", provider);

          // The ticket must name this webhook's own callback URL.
          const external = resolveExternalUrl(c, ctx.config);
          const expectedRedirect = external ? `${external.replace(/\/+$/, "")}${OAUTH_CALLBACK_PATH}` : null;
          if (!expectedRedirect || payload.rdu !== expectedRedirect) throw new ConnectFailure("redirect_mismatch");

          if (providerError) throw new ConnectFailure("access_denied");
          if (!code) throw new ConnectFailure("code_missing");

          // Client secret and token URL come from local config / the built-in
          // table; the ticket's copies are only cross-checked.
          const local = ctx.config.oauthProviders?.[provider];
          if (!local?.clientSecret) throw new ConnectFailure("provider_not_configured");
          const tokenUrl = local.tokenUrl ?? BUILTIN_TOKEN_URLS[provider];
          if (!tokenUrl) throw new ConnectFailure("provider_not_configured");
          if (payload.tku !== tokenUrl) throw new ConnectFailure("token_url_mismatch");
          const clientId = local.clientId ?? payload.clid;
          if (!clientId) throw new ConnectFailure("provider_not_configured");
          if (local.clientId && payload.clid !== local.clientId) throw new ConnectFailure("client_mismatch");

          const verifier = await derivePkceVerifier(secret, payload.nonce);
          const form = new URLSearchParams({
            grant_type: "authorization_code",
            code,
            redirect_uri: expectedRedirect,
            client_id: clientId,
            client_secret: local.clientSecret,
            code_verifier: verifier,
          });
          let resp: Response;
          try {
            resp = await fetch(tokenUrl, {
              method: "POST",
              headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
              body: form,
              signal: AbortSignal.timeout(EXCHANGE_TIMEOUT_MS),
            });
          } catch {
            throw new ConnectFailure("exchange_unreachable");
          }
          if (!resp.ok) throw new ConnectFailure("exchange_failed");
          let oauth: { access_token?: unknown; refresh_token?: unknown; expires_in?: unknown; scope?: unknown };
          try {
            oauth = (await resp.json()) as typeof oauth;
          } catch {
            throw new ConnectFailure("exchange_failed");
          }
          if (typeof oauth.access_token !== "string" || !oauth.access_token) throw new ConnectFailure("exchange_failed");
          const refreshToken = typeof oauth.refresh_token === "string" && oauth.refresh_token ? oauth.refresh_token : null;

          const existing = await ctx.storage.get("tokens", service);
          const existingMeta =
            existing?.meta && typeof existing.meta === "object" ? (existing.meta as Record<string, unknown>) : {};
          const now = nowIso();
          const meta: Record<string, unknown> = {
            serviceName: service,
            tokenType: "oauth",
            provider,
            oauth: { provider, tokenUrl, clientId },
            hasRefreshToken: refreshToken != null,
            updatedAt: now,
            createdAt: typeof existingMeta.createdAt === "string" ? existingMeta.createdAt : now,
          };
          if (typeof existingMeta.creationId === "string") meta.creationId = existingMeta.creationId;
          if (typeof oauth.scope === "string" && oauth.scope) meta.scope = oauth.scope;
          if (typeof oauth.expires_in === "number" && oauth.expires_in > 0) {
            meta.expiryTime = Date.now() + oauth.expires_in * 1000;
          }

          const key = await ctx.secrets.encryptionKey();
          await ctx.storage.set("tokens", service, await buildEncryptedTokenDocument(key, oauth.access_token, refreshToken, meta));

          return done({ status: "ok" });
        } catch (e) {
          if (e instanceof ConnectFailure) return done({ status: "error", code: e.code });
          console.error("[oauth-callback] unexpected failure");
          return done({ status: "error", code: "internal_error" });
        }
      });
    },
  };
}
