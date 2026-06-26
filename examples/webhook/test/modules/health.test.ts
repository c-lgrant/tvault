// GET /v1/health reflects the request Origin so the TV bind UI's in-browser
// liveness probe isn't CORS-blocked. The functional capability re-sync is the
// HMAC POST (covered elsewhere); this only guards the browser-readable GET/HEAD.

import { describe, expect, it } from "vitest";
import { createApp } from "../../src/core/app.ts";
import { healthModule } from "../../src/modules/health.ts";
import { makeContext } from "../conformance/_harness.ts";

const secret = crypto.getRandomValues(new Uint8Array(32)) as Uint8Array<ArrayBuffer>;

describe("health CORS", () => {
  it("reflects the request Origin on GET /v1/health", async () => {
    const app = createApp(makeContext({ hmacSecret: secret }), [healthModule()]);
    const res = await app.request("/v1/health", { headers: { origin: "https://tokenvault.one" } });
    expect(res.status).toBe(200);
    expect(res.headers.get("access-control-allow-origin")).toBe("https://tokenvault.one");
    expect(await res.json()).toMatchObject({ status: "healthy" });
  });

  it("answers the OPTIONS preflight with reflected CORS", async () => {
    const app = createApp(makeContext({ hmacSecret: secret }), [healthModule()]);
    const res = await app.request("/v1/health", {
      method: "OPTIONS",
      headers: { origin: "https://tokenvault.one" },
    });
    expect(res.status).toBe(204);
    expect(res.headers.get("access-control-allow-origin")).toBe("https://tokenvault.one");
  });
});
