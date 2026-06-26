// HMAC authentication middleware for TV→webhook requests (auth.py:21-74).
// Order mirrors the reference: setup check → header check → timestamp window →
// duplicate request-id → signature. Used on /v1/storage, /v1/proxy,
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

export const hmacAuth = (ctx: RuntimeContext): MiddlewareHandler<AppEnv> => async (c, next) => {
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
    await guardRequestId(ctx.replay, requestId);
    const secret = await ctx.secrets.hmacSecret();
    const ok = await verifyRequestSignature(secret, ts, c.get("rawBody"), sig.slice(7));
    if (!ok) return sendError(c, authFailed("Invalid HMAC signature"));
  } catch (e) {
    return sendError(c, e);
  }

  await next();
};
