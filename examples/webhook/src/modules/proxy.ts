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
import { healDoc } from "../core/protocol/totpHeal.ts";
import { freshDocument } from "../core/protocol/oauthRefresh.ts";
import { backgroundRunner } from "../core/middleware/background.ts";
import type { FeatureModule } from "../core/registry.ts";
import { isGcpServiceAccount, mintGcpAccessToken } from "./interceptors/gcpSa.ts";

// Hop-by-hop headers not forwarded from the upstream response (proxy.py:118).
const HOP_BY_HOP = new Set(["content-encoding", "content-length", "transfer-encoding", "connection"]);
const UPSTREAM_TIMEOUT_MS = 30_000;
const MAX_REDIRECTS = 5;

/** No upstream chunk for this long ends the stream. Total stream time is not capped. */
export const STREAM_IDLE_TIMEOUT_MS = 60_000;

/**
 * Pass a body through, erroring it if the upstream sends nothing for `ms`. The
 * clock runs only while waiting on the upstream (not while the reader is slow).
 */
function withIdleTimeout(body: ReadableStream<Uint8Array>, ms: number, onIdle: () => void): ReadableStream<Uint8Array> {
  const reader = body.getReader();
  let timer: ReturnType<typeof setTimeout> | undefined;
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      timer = setTimeout(() => {
        onIdle();
        controller.error(new Error("upstream stream idle timeout"));
        reader.cancel().catch(() => {});
      }, ms);
      try {
        const { done, value } = await reader.read();
        clearTimeout(timer);
        if (done) controller.close();
        else controller.enqueue(value);
      } catch (e) {
        clearTimeout(timer);
        controller.error(e);
      }
    },
    cancel(reason) {
      clearTimeout(timer);
      return reader.cancel(reason);
    },
  });
}

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
            // Raw read: the TOTP-heal wrapper can write, and nothing may be
            // written until the replay, purpose and service checks have passed.
            (ctx.rawStorage ?? ctx.storage).get("tokens", service),
          );

          if (payload.pur !== "proxy") return fail(ticketInvalid("Ticket purpose must be 'proxy'"));
          if (payload.svc !== service) {
            return fail(ticketInvalid(`Ticket is for service '${payload.svc}', not '${service}'`));
          }
          if (!storedDoc) return fail(tokenNotFound(`No token stored for service '${service}'`));

          assertCreationMatches(payload, storedDoc);
          storedDoc = (await healDoc(ctx, ctx.rawStorage ?? ctx.storage, "tokens", service, storedDoc)).doc;
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
            const value = String(template).replaceAll("${TOKEN}", accessToken);
            // A credential with a control character (or a non-Latin-1 one) cannot
            // be a header value. Refuse it here with a fixed message: the runtime's
            // own error would quote the value, and it must never leave the webhook.
            // eslint-disable-next-line no-control-regex
            if (/[\r\n\0]|[^\u0000-ÿ]/.test(value)) {
              throw invalidRequest(`Header '${name.replace(/[^\w-]/g, "?").slice(0, 64)}' cannot be rendered from the stored credential`);
            }
            headers.set(name, value);
          }

          const method = (upstream.method ?? "GET").toUpperCase();
          const reqBody = upstream.body ? base64Decode(upstream.body) : undefined;

          // The timeout covers getting response headers only. Once they arrive
          // the timer is cleared, so a long-lived body (an SSE stream) is never
          // aborted; it streams straight through to the caller.
          const abort = new AbortController();
          // The caller leaving (client disconnect, TV's own timeout) ends the
          // upstream call too, headers phase and body phase alike.
          const callerSignal = c.req.raw.signal;
          if (callerSignal.aborted) abort.abort();
          else callerSignal.addEventListener("abort", () => abort.abort(), { once: true });
          let timedOut = false;
          const timer = setTimeout(() => {
            timedOut = true;
            abort.abort();
          }, UPSTREAM_TIMEOUT_MS);
          let upstreamResp: Response;
          tUp0 = performance.now();
          try {
            // Redirects are never followed by the runtime: the injected headers
            // carry the credential and must not leave the registered origin.
            let target = new URL(upstream.url);
            const origin = target.origin;
            let hopMethod = method;
            let hopBody: Uint8Array | undefined = reqBody;
            let hopHeaders = headers;
            for (let hop = 0; ; hop++) {
              upstreamResp = await fetch(target, {
                method: hopMethod,
                headers: hopHeaders,
                ...(hopBody ? { body: hopBody as Uint8Array<ArrayBuffer> } : {}),
                redirect: "manual",
                signal: abort.signal,
              });
              const status = upstreamResp.status;
              const location = upstreamResp.headers.get("location");
              if (![301, 302, 303, 307, 308].includes(status) || !location || hop >= MAX_REDIRECTS) break;
              let next: URL;
              try {
                next = new URL(location, target);
              } catch {
                break;
              }
              if (next.origin !== origin) break;
              if (status === 307 || status === 308) {
                // Same method and body; both are replayable (a buffered array).
              } else if (status === 303 ? hopMethod !== "HEAD" : hopMethod === "POST") {
                hopMethod = "GET";
                hopBody = undefined;
                hopHeaders = new Headers(hopHeaders);
                hopHeaders.delete("content-type");
                hopHeaders.delete("content-length");
              }
              upstreamResp.body?.cancel().catch(() => {});
              target = next;
            }
          } catch (err) {
            if (timedOut) return fail(upstreamTimeout("Upstream request timed out"));
            // Fixed text: an error message from the HTTP stack may quote request headers.
            return fail(upstreamError("Upstream request failed"));
          } finally {
            clearTimeout(timer);
          }
          const tUp1 = performance.now();

          const respHeaders: Record<string, string> = {};
          let upstreamTiming = "";
          upstreamResp.headers.forEach((value, k) => {
            const name = k.toLowerCase();
            if (name === "server-timing") {
              // Drop entries named tv-*: the upstream must not forge ours.
              upstreamTiming = value
                .split(",")
                .map((s) => s.trim())
                .filter((s) => s && !s.toLowerCase().startsWith("tv-"))
                .join(", ");
            }
            else if (!HOP_BY_HOP.has(name)) respHeaders[k] = value;
          });
          respHeaders["X-Upstream-Status"] = String(upstreamResp.status);
          // Keep the upstream's own Server-Timing and append ours.
          const own = timing(tUp1);
          respHeaders["Server-Timing"] = upstreamTiming ? `${upstreamTiming}, ${own}` : own;

          const outBody = upstreamResp.body ? withIdleTimeout(upstreamResp.body, STREAM_IDLE_TIMEOUT_MS, () => abort.abort()) : null;
          return new Response(outBody, { status: upstreamResp.status, headers: respHeaders });
        } catch (e) {
          return fail(e);
        }
      });
    },
  };
}
