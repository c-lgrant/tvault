// Best-effort per-isolate token bucket keyed by client IP. Workers isolates
// don't share memory, so this alone is NOT a global limit — it bounds what one
// isolate will do for one hot client (and is the only limiter on Node). The
// durable defense on Workers is a Cloudflare rate-limiting rule; wrangler.toml
// documents the recommended rule.

import type { MiddlewareHandler } from "hono";
import type { AppEnv } from "../app.ts";
import { tooManyRequests } from "../protocol/errors.ts";
import { sendError } from "./respond.ts";

interface Bucket {
  tokens: number;
  last: number;
}

/** Bucket count bound — a scan/spray across many IPs resets rather than OOMs. */
const MAX_BUCKETS = 10_000;

export function rateLimit(opts: { maxPerMinute: number }): MiddlewareHandler<AppEnv> {
  const max = opts.maxPerMinute;
  const refillPerMs = max / 60_000;
  const buckets = new Map<string, Bucket>();

  return async (c, next) => {
    const ip =
      c.req.header("cf-connecting-ip") ||
      c.req.header("x-forwarded-for")?.split(",")[0]?.trim() ||
      c.req.header("x-real-ip") ||
      "unknown";

    const now = Date.now();
    let b = buckets.get(ip);
    if (!b) {
      if (buckets.size >= MAX_BUCKETS) buckets.clear();
      b = { tokens: max, last: now };
      buckets.set(ip, b);
    }
    b.tokens = Math.min(max, b.tokens + (now - b.last) * refillPerMs);
    b.last = now;

    if (b.tokens < 1) {
      const retryAfter = Math.max(1, Math.ceil((1 - b.tokens) / refillPerMs / 1000));
      return sendError(c, tooManyRequests("Too many requests from this address"), {
        "Retry-After": String(retryAfter),
      });
    }
    b.tokens -= 1;
    await next();
  };
}
