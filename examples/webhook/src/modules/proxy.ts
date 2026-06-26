// MCP proxy (routes/proxy.py). TV forwards the agent's upstream request here
// with a signed proxy ticket; the webhook decrypts the credential, substitutes
// ${TOKEN} into the caller's header templates, calls the upstream verbatim, and
// streams the response straight back. TV never sees the credential. Authn is
// BOTH HMAC (TV identity) and the ticket (per-operation authorization).

import { hmacAuth } from "../core/middleware/hmacAuth.ts";
import { readJsonBody } from "../core/middleware/body.ts";
import { sendError } from "../core/middleware/respond.ts";
import { base64Decode } from "../core/crypto/encoding.ts";
import { invalidRequest, ticketInvalid, tokenNotFound, upstreamError, upstreamTimeout } from "../core/protocol/errors.ts";
import { verifyTicket } from "../core/protocol/tickets.ts";
import { decryptTokenField } from "../core/protocol/tokendoc.ts";
import type { FeatureModule } from "../core/registry.ts";
import { isGcpServiceAccount, mintGcpAccessToken } from "./interceptors/gcpSa.ts";

// Hop-by-hop headers not forwarded from the upstream response (proxy.py:118).
const HOP_BY_HOP = new Set(["content-encoding", "content-length", "transfer-encoding", "connection"]);
const UPSTREAM_TIMEOUT_MS = 30_000;

interface UpstreamSpec {
  url?: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string | null;
}

export function proxyModule(): FeatureModule {
  return {
    name: "proxy",
    capability: "proxy",
    register(app, ctx) {
      app.post("/v1/proxy", hmacAuth(ctx), async (c) => {
        try {
          const body = readJsonBody(c);
          const ticket = typeof body.ticket === "string" ? body.ticket : "";
          const service = typeof body.service === "string" ? body.service : "";
          const upstream = (body.upstream && typeof body.upstream === "object" ? body.upstream : {}) as UpstreamSpec;
          const headerTemplates =
            body.headerTemplates && typeof body.headerTemplates === "object"
              ? (body.headerTemplates as Record<string, string>)
              : {};

          if (!ticket || !service) return sendError(c, invalidRequest("Missing 'ticket' or 'service'"));
          if (!upstream.url) return sendError(c, invalidRequest("Missing 'upstream.url'"));

          const secret = await ctx.secrets.hmacSecret();
          const payload = await verifyTicket(ticket, secret, ctx.replay);
          if (payload.pur !== "proxy") return sendError(c, ticketInvalid("Ticket purpose must be 'proxy'"));
          if (payload.svc !== service) {
            return sendError(c, ticketInvalid(`Ticket is for service '${payload.svc}', not '${service}'`));
          }

          const storedDoc = await ctx.storage.get("tokens", service);
          if (!storedDoc) return sendError(c, tokenNotFound(`No token stored for service '${service}'`));

          const key = await ctx.secrets.encryptionKey();
          let accessToken: string | null;
          if ("fields" in storedDoc) {
            accessToken = await decryptTokenField(key, storedDoc, "accessToken");
          } else {
            accessToken = storedDoc.accessToken != null ? String(storedDoc.accessToken) : null;
          }
          if (!accessToken) return sendError(c, tokenNotFound(`No accessToken found for service '${service}'`));

          // GCP SA key → mint a short-lived token and inject that instead.
          if (isGcpServiceAccount(accessToken)) {
            const minted = await mintGcpAccessToken(accessToken, service);
            accessToken = minted.accessToken;
          }

          const headers = new Headers();
          for (const [k, v] of Object.entries(upstream.headers ?? {})) headers.set(k, v);
          for (const [name, template] of Object.entries(headerTemplates)) {
            headers.set(name, template.replaceAll("${TOKEN}", accessToken));
          }

          const method = (upstream.method ?? "GET").toUpperCase();
          const reqBody = upstream.body ? base64Decode(upstream.body) : undefined;

          let upstreamResp: Response;
          try {
            upstreamResp = await fetch(upstream.url, {
              method,
              headers,
              ...(reqBody ? { body: reqBody as Uint8Array<ArrayBuffer> } : {}),
              signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
            });
          } catch (err) {
            if (err instanceof DOMException && err.name === "TimeoutError") {
              return sendError(c, upstreamTimeout("Upstream request timed out"));
            }
            return sendError(c, upstreamError(`Upstream request failed: ${err instanceof Error ? err.message : String(err)}`));
          }

          const respHeaders: Record<string, string> = {};
          upstreamResp.headers.forEach((value, k) => {
            if (!HOP_BY_HOP.has(k.toLowerCase())) respHeaders[k] = value;
          });
          respHeaders["X-Upstream-Status"] = String(upstreamResp.status);

          const payloadBytes = new Uint8Array(await upstreamResp.arrayBuffer());
          return c.body(payloadBytes, upstreamResp.status as 200, respHeaders);
        } catch (e) {
          return sendError(c, e);
        }
      });
    },
  };
}
