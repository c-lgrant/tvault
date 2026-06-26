// TV-mediated refresh (refresh.py:34-184). THE ONE endpoint where Token Vault
// receives credential material — used only for TV's built-in OAuth providers
// (Google, GitHub) where TV owns the client_secret. Two phases:
//   action "get"    → return the decrypted refresh token to TV (in transit only)
//   action "update" → accept TV's new tokens, encrypt, and store
// Killswitch: drop this module (or TV's `tv-refresh` capability) and TV has no
// credential path of any kind. Authn is HMAC (TV identity).

import { hmacAuth } from "../core/middleware/hmacAuth.ts";
import { readJsonBody } from "../core/middleware/body.ts";
import { sendError } from "../core/middleware/respond.ts";
import { invalidRequest } from "../core/protocol/errors.ts";
import { buildEncryptedTokenDocument, decryptTokenField } from "../core/protocol/tokendoc.ts";
import type { RuntimeContext } from "../runtime/context.ts";
import type { FeatureModule } from "../core/registry.ts";

function nowIso(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

async function handleGet(ctx: RuntimeContext, service: string, requestId: string) {
  const storedDoc = await ctx.storage.get("tokens", service);
  if (!storedDoc) {
    return { requestId, status: "no_token", message: `No token stored for service '${service}'` };
  }
  const key = await ctx.secrets.encryptionKey();
  let refreshToken: string | null;
  if ("fields" in storedDoc) {
    refreshToken = await decryptTokenField(key, storedDoc, "refreshToken");
  } else {
    refreshToken = storedDoc.refreshToken != null ? String(storedDoc.refreshToken) : null;
  }
  if (!refreshToken) {
    return { requestId, status: "no_refresh_token", message: `No refresh token found for service '${service}'` };
  }
  const meta = storedDoc.meta && typeof storedDoc.meta === "object" ? storedDoc.meta : {};
  return { requestId, status: "ok", refreshToken, meta };
}

async function handleUpdate(
  ctx: RuntimeContext,
  service: string,
  tokens: Record<string, unknown>,
  requestId: string,
) {
  const storedDoc = await ctx.storage.get("tokens", service);
  if (!storedDoc) {
    return { requestId, status: "no_token", message: `No existing token to update for service '${service}'` };
  }
  const existingMeta = (storedDoc.meta && typeof storedDoc.meta === "object" ? storedDoc.meta : {}) as Record<
    string,
    unknown
  >;
  const newAccess = tokens.accessToken != null ? String(tokens.accessToken) : null;
  const newRefresh = tokens.refreshToken != null ? String(tokens.refreshToken) : null;
  const expiryTime = typeof tokens.expiryTime === "number" ? tokens.expiryTime : undefined;

  const updatedMeta: Record<string, unknown> = { ...existingMeta, updatedAt: nowIso() };
  if (expiryTime) updatedMeta.expiryTime = expiryTime;
  updatedMeta.hasRefreshToken = newRefresh != null && newRefresh.length > 0;

  const key = await ctx.secrets.encryptionKey();
  const doc = await buildEncryptedTokenDocument(key, newAccess, newRefresh, updatedMeta);
  await ctx.storage.set("tokens", service, doc);

  const newExpiresAt = expiryTime ? new Date(expiryTime).toISOString() : "";
  return { requestId, status: "updated", newExpiresAt };
}

export function tvRefreshModule(): FeatureModule {
  return {
    name: "tv-refresh",
    capability: "tv-refresh",
    register(app, ctx) {
      app.post("/v1/refresh", hmacAuth(ctx), async (c) => {
        try {
          const body = readJsonBody(c);
          const requestId =
            typeof body.requestId === "string" ? body.requestId : (c.req.header("X-TokenVault-Request-Id") ?? "unknown");
          const action = typeof body.action === "string" ? body.action : "";
          const service = typeof body.service === "string" ? body.service : "";
          if (!service) return sendError(c, invalidRequest("Missing 'service'"));

          if (action === "get") {
            return c.json(await handleGet(ctx, service, requestId));
          }
          if (action === "update") {
            const tokens = body.tokens && typeof body.tokens === "object" ? (body.tokens as Record<string, unknown>) : null;
            if (!tokens) return sendError(c, invalidRequest("Missing 'tokens' object"));
            return c.json(await handleUpdate(ctx, service, tokens, requestId));
          }
          return sendError(c, invalidRequest(`Unknown action: '${action}'. Must be 'get' or 'update'.`));
        } catch (e) {
          return sendError(c, e);
        }
      });
    },
  };
}
