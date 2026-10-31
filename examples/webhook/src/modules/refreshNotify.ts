// Autonomous OAuth refresh (refresh.py:187-319). TV notifies the webhook that a
// token is expiring; the webhook owns the credential and performs the refresh
// itself. This is the default, fully zero-knowledge refresh path.
//
// DIVERGENCE FROM THE PYTHON REFERENCE (deliberate): the client secret is read
// from LOCAL provider config (ctx.config.oauthProviders), NEVER from the
// TV-supplied refresh hint. The reference trusts hint.clientSecret
// (refresh.py:246) — that lets the control plane influence the credential
// exchange, which breaks the trust model. Here the client secret goes only to
// a token URL from local config or the built-in table (google, github,
// spotify); a hint naming any other URL is refused. The hint may supply only
// a non-secret clientId, and only when local config has none.

import { hmacAuth } from "../core/middleware/hmacAuth.ts";
import { readJsonBody } from "../core/middleware/body.ts";
import { sendError } from "../core/middleware/respond.ts";
import { invalidRequest } from "../core/protocol/errors.ts";
import { buildEncryptedTokenDocument, decryptTokenField } from "../core/protocol/tokendoc.ts";
import { BUILTIN_TOKEN_URLS } from "../core/protocol/oauthConnect.ts";
import type { FeatureModule } from "../core/registry.ts";

function nowIso(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

interface RefreshHint {
  provider?: string;
  tokenUrl?: string;
  clientId?: string;
}

export function refreshNotifyModule(): FeatureModule {
  return {
    name: "refresh-notify",
    capability: "refresh",
    register(app, ctx) {
      app.post("/v1/refresh-notify", hmacAuth(ctx), async (c) => {
        try {
          const body = readJsonBody(c);
          const requestId =
            typeof body.requestId === "string" ? body.requestId : (c.req.header("X-TokenVault-Request-Id") ?? "unknown");
          const service = typeof body.service === "string" ? body.service : "";
          const hint = (body.refreshHint && typeof body.refreshHint === "object" ? body.refreshHint : {}) as RefreshHint;

          if (!service) return sendError(c, invalidRequest("Missing 'service'"));

          const storedDoc = await ctx.storage.get("tokens", service);
          if (!storedDoc) {
            return c.json({ requestId, status: "no_token", message: `No token stored for service '${service}'` });
          }

          const key = await ctx.secrets.encryptionKey();
          let refreshToken: string | null;
          if ("fields" in storedDoc) {
            refreshToken = await decryptTokenField(key, storedDoc, "refreshToken");
          } else {
            refreshToken = storedDoc.refreshToken != null ? String(storedDoc.refreshToken) : null;
          }
          if (!refreshToken) {
            return c.json({ requestId, status: "no_refresh_token", message: `No refreshToken found for service '${service}'` });
          }

          const existingMeta = (storedDoc.meta && typeof storedDoc.meta === "object" ? storedDoc.meta : {}) as Record<
            string,
            unknown
          >;

          // Client secret comes from LOCAL config only; tokenUrl/clientId may
          // fall back to the (non-secret) hint fields.
          // A token minted by this webhook's own /v1/oauth/callback records a
          // non-secret `oauth` hint in its meta; that outranks the TV-supplied
          // hint (which can only describe TV's built-in providers).
          const stored = (existingMeta.oauth && typeof existingMeta.oauth === "object" ? existingMeta.oauth : {}) as RefreshHint;
          const provider = (stored.provider ?? hint.provider ?? "").toLowerCase();
          const local = ctx.config.oauthProviders?.[provider];
          const clientSecret = local?.clientSecret;
          // The client secret only ever goes to a token URL the operator
          // configured or the built-in table names. The stored and TV-supplied
          // hints are cross-checks: a different URL is refused, never followed.
          const tokenUrl = local?.tokenUrl ?? BUILTIN_TOKEN_URLS[provider];
          const clientId = local?.clientId ?? stored.clientId ?? hint.clientId;

          if (clientSecret && tokenUrl) {
            for (const claimed of [stored.tokenUrl, hint.tokenUrl]) {
              if (claimed && claimed !== tokenUrl) {
                return c.json({ requestId, status: "refresh_failed", message: "Token URL does not match this webhook's provider config" });
              }
            }
            // The webhook's own record of the client that minted the token must
            // match the configured one (the TV hint's id is TV's, so it is not checked).
            if (local?.clientId && stored.clientId && stored.clientId !== local.clientId) {
              return c.json({ requestId, status: "refresh_failed", message: "Client id does not match this webhook's provider config" });
            }
          }

          if (!tokenUrl || !clientId || !clientSecret) {
            // No local credentials to refresh with — acknowledge only.
            return c.json({
              requestId,
              status: "acknowledged",
              message: "Notification received but no local provider credentials for auto-refresh",
            });
          }

          const form = new URLSearchParams({
            grant_type: "refresh_token",
            client_id: clientId,
            client_secret: clientSecret,
            refresh_token: refreshToken,
          });
          const headers: Record<string, string> = { "content-type": "application/x-www-form-urlencoded" };
          if (provider === "github") headers.accept = "application/json";

          const oauthResp = await fetch(tokenUrl, { method: "POST", headers, body: form });
          if (oauthResp.status >= 400) {
            return c.json({ requestId, status: "refresh_failed", message: `OAuth provider returned ${oauthResp.status}` });
          }

          const oauth = (await oauthResp.json()) as {
            access_token?: string;
            refresh_token?: string;
            expires_in?: number;
          };
          const newAccess = oauth.access_token ?? "";
          const newRefresh = oauth.refresh_token ?? refreshToken;
          const expiresIn = typeof oauth.expires_in === "number" ? oauth.expires_in : 3600;
          const expiryMs = Date.now() + expiresIn * 1000;

          const updatedMeta: Record<string, unknown> = {
            serviceName: service,
            tokenType: existingMeta.tokenType ?? provider ?? "oauth",
            expiryTime: expiryMs,
            updatedAt: nowIso(),
          };
          if ("createdAt" in existingMeta) updatedMeta.createdAt = existingMeta.createdAt;
          // Keep what /v1/oauth/callback recorded so the next refresh still works.
          for (const k of ["oauth", "provider", "scope"] as const) {
            if (existingMeta[k] != null) updatedMeta[k] = existingMeta[k];
          }

          const doc = await buildEncryptedTokenDocument(key, newAccess, newRefresh, updatedMeta);
          await ctx.storage.set("tokens", service, doc);

          return c.json({ requestId, status: "refreshed", newExpiresAt: new Date(expiryMs).toISOString() });
        } catch (e) {
          return sendError(c, e);
        }
      });
    },
  };
}
