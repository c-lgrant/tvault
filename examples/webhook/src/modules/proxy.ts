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
import type { MiddlewareHandler } from "hono";
import type { AppEnv } from "../core/app.ts";
import { consumeTicketNonce, verifyTicketSignature } from "../core/protocol/tickets.ts";
import { readAfterReplayChecks } from "../core/protocol/replay.ts";
import { decryptTokenField } from "../core/protocol/tokendoc.ts";
import { assertCreationMatches } from "../core/protocol/constraints.ts";
import { freshDocument } from "../core/protocol/oauthRefresh.ts";
import { backgroundRunner } from "../core/middleware/background.ts";
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
      const stampStart: MiddlewareHandler<AppEnv> = async (c, next) => {
        c.set("t0", performance.now());
        await next();
      };
      app.post("/v1/proxy", stampStart, hmacAuth(ctx, { deferReplay: true }), async (c) => {
        const t0 = c.get("t0") ?? performance.now();
        let tUp0: number | undefined;
        // Durations only (ms, one decimal): no names, errors or ids.
        const timing = (tUp1?: number): string => {
          const wh = `tv-wh;dur=${((tUp0 ?? performance.now()) - t0).toFixed(1)}`;
          return tUp1 === undefined || tUp0 === undefined ? wh : `${wh}, tv-up;dur=${(tUp1 - tUp0).toFixed(1)}`;
        };
        const fail = (e: unknown): Response => {
          const res = sendError(c, e);
          res.headers.set("Server-Timing", timing());
          return res;
        };
        try {
          const body = readJsonBody(c);
          const ticket = typeof body.ticket === "string" ? body.ticket : "";
          const service = typeof body.service === "string" ? body.service : "";
          const upstream = (body.upstream && typeof body.upstream === "object" ? body.upstream : {}) as UpstreamSpec;
          const headerTemplates =
            body.headerTemplates && typeof body.headerTemplates === "object"
              ? (body.headerTemplates as Record<string, string>)
              : {};

          if (!ticket || !service) return fail(invalidRequest("Missing 'ticket' or 'service'"));
          if (!upstream.url) return fail(invalidRequest("Missing 'upstream.url'"));

          // Both signatures (request HMAC in hmacAuth, ticket here) are CPU-only
          // and have passed before any I/O starts. Then the request-id check, the
          // nonce check and the storage read run concurrently; nothing below
          // (decrypt, upstream fetch, response) happens until both replay checks
          // have passed.
          const secret = await ctx.secrets.hmacSecret();
          const payload = await verifyTicketSignature(ticket, secret);
          const guardRid = c.get("guardRequestId");
          if (!guardRid) throw new Error("request-id replay guard was not installed");
          let storedDoc = await readAfterReplayChecks(
            [guardRid(), consumeTicketNonce(payload, ctx.replay)],
            ctx.storage.get("tokens", service),
          );

          if (payload.pur !== "proxy") return fail(ticketInvalid("Ticket purpose must be 'proxy'"));
          if (payload.svc !== service) {
            return fail(ticketInvalid(`Ticket is for service '${payload.svc}', not '${service}'`));
          }
          if (!storedDoc) return fail(tokenNotFound(`No token stored for service '${service}'`));

          assertCreationMatches(payload, storedDoc);
          storedDoc = await freshDocument(ctx, service, storedDoc, backgroundRunner(c));

          const key = await ctx.secrets.encryptionKey();
          let accessToken: string | null;
          if ("fields" in storedDoc) {
            accessToken = await decryptTokenField(key, storedDoc, "accessToken");
          } else {
            accessToken = storedDoc.accessToken != null ? String(storedDoc.accessToken) : null;
          }
          if (!accessToken) return fail(tokenNotFound(`No accessToken found for service '${service}'`));

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

          // The timeout covers getting response headers only. Once they arrive
          // the timer is cleared, so a long-lived body (an SSE stream) is never
          // aborted; it streams straight through to the caller.
          const abort = new AbortController();
          let timedOut = false;
          const timer = setTimeout(() => {
            timedOut = true;
            abort.abort();
          }, UPSTREAM_TIMEOUT_MS);
          let upstreamResp: Response;
          tUp0 = performance.now();
          try {
            upstreamResp = await fetch(upstream.url, {
              method,
              headers,
              ...(reqBody ? { body: reqBody as Uint8Array<ArrayBuffer> } : {}),
              signal: abort.signal,
            });
          } catch (err) {
            if (timedOut) return fail(upstreamTimeout("Upstream request timed out"));
            return fail(upstreamError(`Upstream request failed: ${err instanceof Error ? err.message : String(err)}`));
          } finally {
            clearTimeout(timer);
          }
          const tUp1 = performance.now();

          const respHeaders: Record<string, string> = {};
          let upstreamTiming = "";
          upstreamResp.headers.forEach((value, k) => {
            const name = k.toLowerCase();
            if (name === "server-timing") upstreamTiming = value;
            else if (!HOP_BY_HOP.has(name)) respHeaders[k] = value;
          });
          respHeaders["X-Upstream-Status"] = String(upstreamResp.status);
          // Keep the upstream's own Server-Timing and append ours.
          const own = timing(tUp1);
          respHeaders["Server-Timing"] = upstreamTiming ? `${upstreamTiming}, ${own}` : own;

          return new Response(upstreamResp.body, { status: upstreamResp.status, headers: respHeaders });
        } catch (e) {
          return fail(e);
        }
      });
    },
  };
}
