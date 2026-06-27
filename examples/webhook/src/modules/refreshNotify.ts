// Autonomous OAuth refresh (refresh.py:187-319). TV notifies the webhook that a
// token is expiring; the webhook owns the credential and performs the refresh
// itself. This is the default, fully zero-knowledge refresh path.
//
// DIVERGENCE FROM THE PYTHON REFERENCE (deliberate): the client secret is read
// from LOCAL provider config (ctx.config.oauthProviders), NEVER from the
// TV-supplied refresh hint. The reference trusts hint.clientSecret
// (refresh.py:246) — that lets the control plane influence the credential
// exchange, which breaks the trust model. Here the hint may supply only the
// non-secret tokenUrl/clientId (and even those prefer local config).

import { hmacAuth } from "../core/middleware/hmacAuth.ts";
import { readJsonBody } from "../core/middleware/body.ts";
import { sendError } from "../core/middleware/respond.ts";
import { invalidRequest } from "../core/protocol/errors.ts";
import { buildEncryptedTokenDocument, decryptTokenField } from "../core/protocol/tokendoc.ts";
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
          const provider = (hint.provider ?? "").toLowerCase();
          const local = ctx.config.oauthProviders?.[provider];
          const clientSecret = local?.clientSecret;
          const tokenUrl = local?.tokenUrl ?? hint.tokenUrl;
          const clientId = local?.clientId ?? hint.clientId;

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
