// Capture the raw request bytes exactly as received, before anything parses
// them. HMAC verification must run over these literal bytes (TV signs the
// compact JSON it serialized); re-serializing from a parsed object would change
// key order/whitespace and break the signature.
//
// The body is buffered before any authentication, so it is capped: a declared
// Content-Length over the limit is refused without reading, and a body without
// one (chunked) is counted as it streams and cut off at the limit.

import type { MiddlewareHandler } from "hono";
import type { AppEnv } from "../app.ts";
import { WebhookError } from "../protocol/errors.ts";

export const DEFAULT_MAX_BODY_BYTES = 1024 * 1024;
export const DEFAULT_MAX_PROXY_BODY_BYTES = 16 * 1024 * 1024;

export interface BodyLimits {
  maxBodyBytes?: number;
  maxProxyBodyBytes?: number;
}

const tooLarge = () => new WebhookError(413, "payload_too_large", "Request body is too large.");

export const rawBody = (limits: BodyLimits = {}): MiddlewareHandler<AppEnv> => async (c, next) => {
  const max =
    c.req.path === "/v1/proxy"
      ? (limits.maxProxyBodyBytes ?? DEFAULT_MAX_PROXY_BODY_BYTES)
      : (limits.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES);

  const declared = c.req.header("content-length");
  if (declared !== undefined && /^\d+$/.test(declared) && Number(declared) > max) throw tooLarge();

  const stream = c.req.raw.body;
  let buf: Uint8Array<ArrayBuffer>;
  if (!stream) {
    buf = new Uint8Array(0);
  } else {
    const reader = stream.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > max) {
        reader.cancel().catch(() => {});
        throw tooLarge();
      }
      chunks.push(value);
    }
    buf = new Uint8Array(total);
    let off = 0;
    for (const chunk of chunks) {
      buf.set(chunk, off);
      off += chunk.byteLength;
    }
  }
  c.set("rawBody", buf);
  await next();
};
