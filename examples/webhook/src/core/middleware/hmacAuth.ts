// HMAC authentication middleware for TV→webhook requests (auth.py:21-74).
// Order: setup check → header check → timestamp window → signature → signed
// attemptId matches the request-id header → duplicate request-id. The id is
// recorded only for a signed request. Used on /v1/storage, /v1/proxy,
// /v1/refresh, /v1/refresh-notify, and POST /v1/health.

import type { MiddlewareHandler } from "hono";
import type { AppEnv } from "../app.ts";
import type { RuntimeContext } from "../../runtime/context.ts";
import { HEADER_REQUEST_ID, HEADER_SIGNATURE, HEADER_TIMESTAMP } from "../protocol/types.ts";
import { authFailed, setupRequired } from "../protocol/errors.ts";
import { verifyRequestSignature } from "../protocol/hmac.ts";
import { guardRequestId } from "../protocol/replay.ts";
import { sendError } from "./respond.ts";

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

/**
 * Parse the signed body once. Returns the parsed value (undefined when empty or
 * not JSON) and the `attemptId` it carries, if any.
 */
function parseSignedBody(rawBody: Uint8Array | undefined): { parsed?: unknown; attemptId?: string } {
  if (!rawBody || rawBody.length === 0) return {};
  try {
    const parsed: unknown = JSON.parse(new TextDecoder().decode(rawBody));
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      const v = (parsed as Record<string, unknown>).attemptId;
      return { parsed, ...(typeof v === "string" ? { attemptId: v } : {}) };
    }
    return { parsed };
  } catch {
    // Not JSON: nothing to cross-check.
    return {};
  }
}

export interface HmacAuthOptions {
  /**
   * Verify the signature here but leave the request-id replay check to the
   * handler (`c.get("guardRequestId")`), so it can run concurrently with the
   * handler's other I/O. The handler must not act on the request (no
   * decryption, response or upstream call) until that check has passed.
   */
  deferReplay?: boolean;
}

export const hmacAuth = (ctx: RuntimeContext, opts: HmacAuthOptions = {}): MiddlewareHandler<AppEnv> => async (c, next) => {
  if (!(await ctx.secrets.isConfigured())) return sendError(c, setupRequired());

  const sig = c.req.header(HEADER_SIGNATURE) ?? "";
  const ts = c.req.header(HEADER_TIMESTAMP) ?? "";
  const requestId = c.req.header(HEADER_REQUEST_ID);

  if (!sig.startsWith("sha256=") || !ts) {
    return sendError(c, authFailed("Missing or invalid authentication headers"));
  }

  const tsNum = Number(ts);
  if (!Number.isInteger(tsNum)) {
    return sendError(c, authFailed("Invalid timestamp format"));
  }
  if (Math.abs(nowSeconds() - tsNum) > ctx.config.timestampTolerance) {
    return sendError(c, authFailed("Request timestamp outside acceptable window"));
  }

  try {
    const secret = await ctx.secrets.hmacSecret();
    const rawBody = c.get("rawBody");
    const ok = await verifyRequestSignature(secret, ts, rawBody, sig.slice(7));
    if (!ok) return sendError(c, authFailed("Invalid HMAC signature"));
    // The request-id header is not signed. Spec 2.8.0 puts the same value in the
    // signed body as `attemptId`, so a captured request can't be replayed under a
    // new header id. Older control planes send no attemptId: header only.
    const { parsed, attemptId } = parseSignedBody(rawBody);
    if (parsed !== undefined) c.set("parsedBody", parsed);
    if (attemptId !== undefined && attemptId !== requestId) {
      return sendError(c, authFailed("X-TokenVault-Request-Id does not match the signed attemptId"));
    }
    if (opts.deferReplay) {
      // A missing id needs no I/O to refuse: do it here, ahead of the handler.
      if (!requestId) throw authFailed("Missing X-TokenVault-Request-Id header");
      c.set("guardRequestId", () => guardRequestId(ctx.replay, requestId));
    } else {
      await guardRequestId(ctx.replay, requestId);
    }
  } catch (e) {
    return sendError(c, e);
  }

  await next();
};
