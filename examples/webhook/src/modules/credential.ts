// Zero-knowledge credential retrieval (direct_access.py:139-299). Ticket is the
// auth (no HMAC); the IP/origin denylist runs first so a real ticket replayed
// from TV's server is rejected. Registered credential interceptors (TOTP, GCP)
// transform the credential before it is returned.

import { corsHeaders, preflightResponse } from "../core/middleware/cors.ts";
import { denylist } from "../core/middleware/denylist.ts";
import { readJsonBody } from "../core/middleware/body.ts";
import { sendError } from "../core/middleware/respond.ts";
import { invalidRequest, setupRequired, ticketInvalid, tokenNotFound } from "../core/protocol/errors.ts";
import { consumeTicketNonce, verifyTicketSignature } from "../core/protocol/tickets.ts";
import { readAfterReplayChecks } from "../core/protocol/replay.ts";
import { readTokenObject } from "../core/protocol/tokendoc.ts";
import { assertCreationMatches } from "../core/protocol/constraints.ts";
import { healDoc } from "../core/protocol/totpHeal.ts";
import { freshDocument } from "../core/protocol/oauthRefresh.ts";
import { backgroundRunner } from "../core/middleware/background.ts";
import type { FeatureModule } from "../core/registry.ts";

const CREDENTIAL_PURPOSES = new Set(["agent_credential", "user_reveal"]);

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
          // Signature first (CPU), then the nonce check and the storage read run
          // concurrently; nothing is decrypted or returned until the nonce check
          // has passed.
          const payload = await verifyTicketSignature(ticket, secret);
          let storedDoc = await readAfterReplayChecks(
            [consumeTicketNonce(payload, ctx.replay)],
            // Raw read: the TOTP-heal wrapper can write, and nothing may be
            // written until the replay, purpose and service checks have passed.
            (ctx.rawStorage ?? ctx.storage).get("tokens", service),
          );

          if (!CREDENTIAL_PURPOSES.has(payload.pur)) {
            return sendError(c, ticketInvalid(`Invalid ticket purpose for this endpoint: '${payload.pur}'`), cors);
          }
          if (payload.svc !== service) {
            return sendError(c, ticketInvalid(`Ticket is for service '${payload.svc}', not '${service}'`), cors);
          }

          if (!storedDoc) {
            return sendError(c, tokenNotFound(`No token stored for service '${service}'`), cors);
          }

          assertCreationMatches(payload, storedDoc);
          storedDoc = (await healDoc(ctx, ctx.rawStorage ?? ctx.storage, "tokens", service, storedDoc)).doc;
          // An own-app OAuth token past its expiry is refreshed before it is
          // handed out (best effort; the schedule normally got there first).
          storedDoc = await freshDocument(ctx, service, storedDoc, backgroundRunner(c));

          const key = await ctx.secrets.encryptionKey();
          let token = await readTokenObject(key, storedDoc);

          const query = new URL(c.req.url).searchParams;
          for (const interceptor of registry.interceptors) {
            if (interceptor.matches(token, storedDoc)) {
              token = await interceptor.transform({ token, service, storedDoc, query, ctx });
              break;
            }
          }

          // An agent gets the credential, not the long-lived key that makes more
          // of it, so stopping its access also stops any renewals. This webhook
          // does the refreshing. A person's own reveal (user_reveal) keeps the field.
          if (payload.pur === "agent_credential") delete token.refreshToken;

          return c.json({ token }, 200, cors);
        } catch (e) {
          return sendError(c, e, cors);
        }
      });
    },
  };
}
