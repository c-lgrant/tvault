// Browser-direct token storage (direct_access.py:20-136). The browser posts a
// TV-signed store ticket plus plaintext token data; the webhook verifies the
// ticket, encrypts with its own key, and persists. TV never sees the plaintext.
// Ticket is the auth; the IP/origin denylist runs first.

import { corsHeaders, preflightResponse } from "../core/middleware/cors.ts";
import { denylist } from "../core/middleware/denylist.ts";
import { readJsonBody } from "../core/middleware/body.ts";
import { sendError } from "../core/middleware/respond.ts";
import { invalidRequest, setupRequired, ticketInvalid } from "../core/protocol/errors.ts";
import { verifyTicket } from "../core/protocol/tickets.ts";
import { buildEncryptedTokenDocument, EXTRA_SENSITIVE_FIELDS } from "../core/protocol/tokendoc.ts";
import { SENSITIVE_FIELDS } from "../core/protocol/types.ts";
import type { FeatureModule } from "../core/registry.ts";

function nowIso(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

export function storeModule(): FeatureModule {
  return {
    name: "store",
    capability: "store",
    register(app, ctx) {
      app.options("/v1/store", (c) => preflightResponse(c));

      app.post("/v1/store", denylist(ctx.config), async (c) => {
        const cors = corsHeaders(c.req.header("origin"));
        try {
          if (!(await ctx.secrets.isConfigured())) return sendError(c, setupRequired(), cors);

          const body = readJsonBody(c);
          const ticket = typeof body.ticket === "string" ? body.ticket : "";
          const service = typeof body.service === "string" ? body.service : "";
          const tokenData =
            body.tokenData && typeof body.tokenData === "object"
              ? (body.tokenData as Record<string, unknown>)
              : null;

          if (!ticket) return sendError(c, invalidRequest("Missing 'ticket'"), cors);
          if (!service) return sendError(c, invalidRequest("Missing 'service'"), cors);
          if (!tokenData) return sendError(c, invalidRequest("Missing 'tokenData'"), cors);

          const secret = await ctx.secrets.hmacSecret();
          const payload = await verifyTicket(ticket, secret, ctx.replay);

          if (payload.pur !== "store") {
            return sendError(c, ticketInvalid("Ticket purpose must be 'store'"), cors);
          }
          if (payload.svc !== service) {
            return sendError(c, ticketInvalid(`Ticket is for service '${payload.svc}', not '${service}'`), cors);
          }

          const accessToken = tokenData.accessToken != null ? String(tokenData.accessToken) : null;
          const refreshToken = tokenData.refreshToken != null ? String(tokenData.refreshToken) : null;

          // Meta = every non-sensitive tokenData field, plus required fields.
          const meta: Record<string, unknown> = {};
          for (const [k, v] of Object.entries(tokenData)) {
            if (!SENSITIVE_FIELDS.has(k) && v != null) meta[k] = v;
          }
          meta.serviceName = service;
          if (!("tokenType" in meta)) meta.tokenType = "oauth";
          meta.createdAt = nowIso();
          meta.hasRefreshToken = refreshToken != null && refreshToken.length > 0;
          if (!meta.expiryTime && typeof tokenData.expiresAt === "string") {
            const t = Date.parse(tokenData.expiresAt);
            if (!Number.isNaN(t)) meta.expiryTime = t;
          }

          const extraSensitive: Record<string, unknown> = {};
          for (const sf of EXTRA_SENSITIVE_FIELDS) {
            const val = tokenData[sf];
            if (val) extraSensitive[sf] = val;
          }

          const key = await ctx.secrets.encryptionKey();
          const doc = await buildEncryptedTokenDocument(
            key,
            accessToken,
            refreshToken,
            meta,
            extraSensitive,
          );
          await ctx.storage.set("tokens", service, doc);

          return c.json({ status: "stored", service, meta }, 200, cors);
        } catch (e) {
          return sendError(c, e, cors);
        }
      });
    },
  };
}
