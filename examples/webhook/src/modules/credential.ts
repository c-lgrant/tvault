// Zero-knowledge credential retrieval (direct_access.py:139-299). Ticket is the
// auth (no HMAC); the IP/origin denylist runs first so a real ticket replayed
// from TV's server is rejected. Registered credential interceptors (TOTP, GCP)
// transform the credential before it is returned.

import { corsHeaders, preflightResponse } from "../core/middleware/cors.ts";
import { denylist } from "../core/middleware/denylist.ts";
import { readJsonBody } from "../core/middleware/body.ts";
import { sendError } from "../core/middleware/respond.ts";
import { invalidRequest, setupRequired, ticketInvalid, tokenNotFound } from "../core/protocol/errors.ts";
import { verifyTicket } from "../core/protocol/tickets.ts";
import { readTokenObject } from "../core/protocol/tokendoc.ts";
import type { FeatureModule } from "../core/registry.ts";

// `browser_credential` has no TV issuer (a phantom purpose); accepted here for
// parity with the reference, but never required.
const CREDENTIAL_PURPOSES = new Set(["agent_credential", "user_reveal", "browser_credential"]);

export function credentialModule(): FeatureModule {
  return {
    name: "credential",
    capability: "credential",
    register(app, ctx, registry) {
      app.options("/v1/credential", (c) => preflightResponse(c));

      app.on(["GET", "POST"], "/v1/credential", denylist(ctx.config), async (c) => {
        const cors = corsHeaders(c.req.header("origin"));
        try {
          if (!(await ctx.secrets.isConfigured())) return sendError(c, setupRequired(), cors);

          let ticket = "";
          let service = "";
          if (c.req.method === "GET") {
            const params = new URL(c.req.url).searchParams;
            ticket = params.get("ticket") ?? "";
            service = params.get("service") ?? "";
          } else {
            const body = readJsonBody(c);
            ticket = typeof body.ticket === "string" ? body.ticket : "";
            service = typeof body.service === "string" ? body.service : "";
          }

          if (!ticket) return sendError(c, invalidRequest("Missing 'ticket' parameter"), cors);
          if (!service) return sendError(c, invalidRequest("Missing 'service' parameter"), cors);

          const secret = await ctx.secrets.hmacSecret();
          const payload = await verifyTicket(ticket, secret, ctx.replay);

          if (!CREDENTIAL_PURPOSES.has(payload.pur)) {
            return sendError(c, ticketInvalid(`Invalid ticket purpose for this endpoint: '${payload.pur}'`), cors);
          }
          if (payload.svc !== service) {
            return sendError(c, ticketInvalid(`Ticket is for service '${payload.svc}', not '${service}'`), cors);
          }

          const storedDoc = await ctx.storage.get("tokens", service);
          if (!storedDoc) {
            return sendError(c, tokenNotFound(`No token stored for service '${service}'`), cors);
          }

          const key = await ctx.secrets.encryptionKey();
          let token = await readTokenObject(key, storedDoc);

          const query = new URL(c.req.url).searchParams;
          for (const interceptor of registry.interceptors) {
            if (interceptor.matches(token, storedDoc)) {
              token = await interceptor.transform({ token, service, storedDoc, query, ctx });
              break;
            }
          }

          return c.json({ token }, 200, cors);
        } catch (e) {
          return sendError(c, e, cors);
        }
      });
    },
  };
}
