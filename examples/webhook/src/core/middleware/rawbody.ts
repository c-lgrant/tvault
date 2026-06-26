// Capture the raw request bytes exactly as received, before anything parses
// them. HMAC verification must run over these literal bytes (TV signs the
// compact JSON it serialized); re-serializing from a parsed object would change
// key order/whitespace and break the signature.

import type { MiddlewareHandler } from "hono";
import type { AppEnv } from "../app.ts";

export const rawBody = (): MiddlewareHandler<AppEnv> => async (c, next) => {
  const buf = new Uint8Array(await c.req.arrayBuffer());
  c.set("rawBody", buf);
  await next();
};
