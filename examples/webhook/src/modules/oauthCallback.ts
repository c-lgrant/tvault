// OAuth "connect with your own app" (capability `oauth-callback`).
//
//   GET /v1/oauth/start?state=<ticket>            (the browser lands here first)
//   GET /v1/oauth/callback?code=…&state=<ticket>  (the provider redirects here)
//
// The user registered an OAuth app at the provider with the callback URL as its
// redirect URI, so the authorization code goes straight to the webhook and never
// to the control plane.
//
// start:  verifies the control-plane-signed state ticket WITHOUT consuming it,
//         sets a short-lived HttpOnly cookie holding sha256(nonce), and 302s to
//         the provider's authorize URL, which the webhook builds itself (built-in
//         authorize table or the operator's config; PKCE S256 challenge derived
//         from the HMAC secret + nonce). This binds the flow to the browser that
//         started it, so a victim cannot be tricked into finishing an attacker's
//         flow (OAuth login CSRF / account injection).
// callback: verifies the state (signature, 10 min expiry, names THIS callback
//         URL), requires the cookie to match the nonce, then consumes the nonce
//         (one-shot), exchanges the code with the client secret from LOCAL
//         config and the derived PKCE verifier, stores the result as the named
//         service with a non-secret `oauth` hint (so /v1/refresh-notify works),
//         clears the cookie, and 302s to the Token Vault frontend result page.
//         The redirect carries only a status, the service name and a short error
//         code: never a code, token or provider error text.
//
// The client secret is only ever sent to a token URL the operator configured or
// that is in the built-in table. The ticket's token URL is only cross-checked.

import type { Context } from "hono";
import type { AppEnv } from "../core/app.ts";
import { denylist } from "../core/middleware/denylist.ts";
import { WebhookError } from "../core/protocol/errors.ts";
import {
  BUILTIN_AUTHORIZE,
  BUILTIN_TOKEN_URLS,
  derivePkceVerifier,
  OAUTH_CALLBACK_CAPABILITY,
  OAUTH_CALLBACK_PATH,
  OAUTH_CONNECT_PURPOSE,
  OAUTH_COOKIE,
  OAUTH_START_PATH,
  OAUTH_STATE_TTL_SECONDS,
  pkceChallenge,
  sha256Hex,
} from "../core/protocol/oauthConnect.ts";
import { verifyTicket } from "../core/protocol/tickets.ts";
import { buildEncryptedTokenDocument } from "../core/protocol/tokendoc.ts";
import type { TicketPayload } from "../core/protocol/types.ts";
import type { FeatureModule } from "../core/registry.ts";
import type { ReplayGuard, RuntimeContext } from "../runtime/context.ts";
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

/** Replay guard that records nothing: `start` verifies a state without consuming it. */
const PEEK_ONLY: ReplayGuard = {
  checkRequestId: async () => false,
  checkNonce: async () => false,
};

interface ParsedState {
  payload: TicketPayload;
  provider: string;
  service: string;
  redirectUri: string;
  secret: Uint8Array<ArrayBuffer>;
}

async function parseState(
  c: Context<AppEnv>,
  ctx: RuntimeContext,
  state: string,
  replay: ReplayGuard,
  onNamed: (service: string, provider: string) => void,
): Promise<ParsedState> {
  if (!state) throw new ConnectFailure("state_invalid");
  const secret = await ctx.secrets.hmacSecret();
  let payload: TicketPayload;
  try {
    payload = await verifyTicket(state, secret, replay, OAUTH_STATE_TTL_SECONDS + 60);
  } catch (e) {
    if (e instanceof WebhookError && e.code === "ticket_expired") throw new ConnectFailure("state_expired");
    throw new ConnectFailure("state_invalid");
  }
  if (payload.pur !== OAUTH_CONNECT_PURPOSE) throw new ConnectFailure("state_invalid");
  const service = typeof payload.svc === "string" ? payload.svc : "";
  const provider = typeof payload.prv === "string" ? payload.prv.toLowerCase() : "";
  if (!service || !provider) throw new ConnectFailure("state_invalid");
  onNamed(service, provider);

  // The ticket must name this webhook's own callback URL.
  const external = resolveExternalUrl(c, ctx.config);
  const expected = external ? `${external.replace(/\/+$/, "")}${OAUTH_CALLBACK_PATH}` : null;
  if (!expected || payload.rdu !== expected) throw new ConnectFailure("redirect_mismatch");
  return { payload, provider, service, redirectUri: expected, secret };
}

function readCookie(header: string | undefined, name: string): string | null {
  for (const part of (header ?? "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}

const cookieAttrs = "Path=/v1/oauth; HttpOnly; Secure; SameSite=Lax";

export function oauthCallbackModule(): FeatureModule {
  return {
    name: "oauth-callback",
    capability: OAUTH_CALLBACK_CAPABILITY,
    register(app, ctx) {
      const resultRedirect = (c: Context<AppEnv>, params: Record<string, string>, clearCookie: boolean) => {
        const result = new URL("/tokens/oauth-result", ctx.config.tokenvaultFrontendUrl);
        for (const [k, v] of Object.entries(params)) result.searchParams.set(k, v);
        if (clearCookie) c.header("Set-Cookie", `${OAUTH_COOKIE}=; Max-Age=0; ${cookieAttrs}`);
        return c.redirect(result.toString(), 302);
      };
      const noStore = (c: Context<AppEnv>) => {
        c.header("Cache-Control", "no-store");
        c.header("Referrer-Policy", "no-referrer");
      };

      app.get(OAUTH_START_PATH, denylist(ctx.config), async (c) => {
        noStore(c);
        const named: Record<string, string> = {};
        try {
          if (!(await ctx.secrets.isConfigured())) throw new ConnectFailure("setup_required");
          const st = await parseState(c, ctx, c.req.query("state") ?? "", PEEK_ONLY, (service, provider) => {
            named.service = service;
            named.provider = provider;
          });
          const local = ctx.config.oauthProviders?.[st.provider];
          if (!local?.clientSecret) throw new ConnectFailure("provider_not_configured");
          const builtin = BUILTIN_AUTHORIZE[st.provider];
          const authorizeUrl = local.authorizeUrl ?? builtin?.url;
          if (!authorizeUrl) throw new ConnectFailure("provider_not_configured");
          const clientId = local.clientId ?? st.payload.clid;
          if (!clientId) throw new ConnectFailure("provider_not_configured");
          if (local.clientId && st.payload.clid !== local.clientId) throw new ConnectFailure("client_mismatch");

          const verifier = await derivePkceVerifier(st.secret, st.payload.nonce);
          const url = new URL(authorizeUrl);
          const params: Record<string, string> = {
            response_type: "code",
            client_id: clientId,
            redirect_uri: st.redirectUri,
            state: c.req.query("state")!,
            code_challenge: await pkceChallenge(verifier),
            code_challenge_method: "S256",
            ...(builtin?.extra ?? {}),
          };
          if (st.payload.scp) params.scope = st.payload.scp;
          for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);

          c.header(
            "Set-Cookie",
            `${OAUTH_COOKIE}=${await sha256Hex(st.payload.nonce)}; Max-Age=${OAUTH_STATE_TTL_SECONDS}; ${cookieAttrs}`,
          );
          return c.redirect(url.toString(), 302);
        } catch (e) {
          if (e instanceof ConnectFailure) return resultRedirect(c, { ...named, status: "error", code: e.code }, false);
          console.error("[oauth-start] unexpected failure");
          return resultRedirect(c, { ...named, status: "error", code: "internal_error" }, false);
        }
      });

      app.get(OAUTH_CALLBACK_PATH, denylist(ctx.config), async (c) => {
        noStore(c);
        const named: Record<string, string> = {};
        const done = (params: Record<string, string>) => resultRedirect(c, { ...named, ...params }, true);
        try {
          if (!(await ctx.secrets.isConfigured())) throw new ConnectFailure("setup_required");

          const state = c.req.query("state") ?? "";
          const code = c.req.query("code") ?? "";
          const providerError = c.req.query("error");

          // Verify without consuming, so a request from the wrong browser cannot
          // burn the real browser's one-shot state.
          const st = await parseState(c, ctx, state, PEEK_ONLY, (service, provider) => {
            named.service = service;
            named.provider = provider;
          });
          const { payload, provider, service } = st;

          // The browser that finishes the flow must be the one that started it.
          const cookie = readCookie(c.req.header("cookie"), OAUTH_COOKIE);
          if (!cookie || cookie !== (await sha256Hex(payload.nonce))) throw new ConnectFailure("browser_mismatch");

          // One-shot: consume the nonce now.
          if (await ctx.replay.checkNonce(payload.nonce, OAUTH_STATE_TTL_SECONDS + 60)) {
            throw new ConnectFailure("state_invalid");
          }

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

          const verifier = await derivePkceVerifier(st.secret, payload.nonce);
          const form = new URLSearchParams({
            grant_type: "authorization_code",
            code,
            redirect_uri: st.redirectUri,
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
