// The per-isolate token bucket is best-effort self-protection: a client that
// exceeds rateLimit.maxPerMinute gets 429 + Retry-After instead of burning
// Worker invocations/upstream quota. Real defense is a CF rate-limiting rule
// (wrangler.toml); this bounds damage between rule evaluations and on Node.

import { describe, expect, it } from "vitest";
import { createApp } from "../../src/core/app.ts";
import { healthModule } from "../../src/modules/health.ts";
import { makeContext } from "../conformance/_harness.ts";

const HOST = { "x-forwarded-host": "wh.example", "cf-connecting-ip": "203.0.113.9" };
const secret = crypto.getRandomValues(new Uint8Array(32)) as Uint8Array<ArrayBuffer>;

function appWithLimit(maxPerMinute: number) {
  const ctx = makeContext({ hmacSecret: secret });
  ctx.config.rateLimit = { maxPerMinute };
  return createApp(ctx, [healthModule]);
}

describe("rate limit middleware", () => {
  it("allows requests under the limit", async () => {
    const app = appWithLimit(5);
    for (let i = 0; i < 5; i++) {
      const res = await app.request("https://wh.example/v1/health", { headers: HOST });
      expect(res.status).not.toBe(429);
    }
  });

  it("returns 429 with Retry-After once the bucket is empty", async () => {
    const app = appWithLimit(3);
    for (let i = 0; i < 3; i++) await app.request("https://wh.example/v1/health", { headers: HOST });
    const res = await app.request("https://wh.example/v1/health", { headers: HOST });
    expect(res.status).toBe(429);
    expect(Number(res.headers.get("retry-after"))).toBeGreaterThan(0);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("rate_limited");
  });

  it("buckets are per client IP", async () => {
    const app = appWithLimit(2);
    for (let i = 0; i < 2; i++) await app.request("https://wh.example/v1/health", { headers: HOST });
    const other = { "x-forwarded-host": "wh.example", "cf-connecting-ip": "198.51.100.7" };
    const res = await app.request("https://wh.example/v1/health", { headers: other });
    expect(res.status).not.toBe(429);
  });

  it("is disabled when rateLimit is absent", async () => {
    const app = createApp(makeContext({ hmacSecret: secret }), [healthModule]);
    for (let i = 0; i < 20; i++) {
      const res = await app.request("https://wh.example/v1/health", { headers: HOST });
      expect(res.status).not.toBe(429);
    }
  });
});
