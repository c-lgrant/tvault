// tv-refresh is opt-in: TV_REFRESH_ENABLED=true registers the module and
// advertises the capability; otherwise it is absent from /v1/health.

import { describe, expect, it } from "vitest";
import { createApp } from "../../src/core/app.ts";
import { allModules } from "../../src/modules/index.ts";
import { configFromEnv } from "../../src/runtime/config.ts";
import { makeContext } from "../conformance/_harness.ts";

const secret = crypto.getRandomValues(new Uint8Array(32)) as Uint8Array<ArrayBuffer>;

async function capabilities(enabled: boolean): Promise<string[]> {
  const app = createApp(makeContext({ hmacSecret: secret }), allModules({ tvRefreshEnabled: enabled }));
  const res = await app.request("/v1/health");
  return ((await res.json()) as { capabilities: string[] }).capabilities;
}

describe("tv-refresh opt-in", () => {
  it("is off by default", async () => {
    const app = createApp(makeContext({ hmacSecret: secret }), allModules());
    const body = (await (await app.request("/v1/health")).json()) as { capabilities: string[] };
    expect(body.capabilities).not.toContain("tv-refresh");
    expect(body.capabilities).toContain("refresh");
  });

  it("advertises tv-refresh in canonical order when enabled", async () => {
    const caps = await capabilities(true);
    expect(caps.indexOf("tv-refresh")).toBe(caps.indexOf("refresh") + 1);
  });

  it("omits it from the capability list when disabled", async () => {
    expect(await capabilities(false)).not.toContain("tv-refresh");
  });

  it("does not route /v1/refresh when disabled", async () => {
    const app = createApp(makeContext({ hmacSecret: secret }), allModules({ tvRefreshEnabled: false }));
    const res = await app.request("/v1/refresh", { method: "POST", body: "{}" });
    expect(res.status).toBe(404);
  });

  it("reads TV_REFRESH_ENABLED from env: only the string true enables it", () => {
    const base = { TOKENVAULT_FRONTEND_URL: "https://tv.test" } as Record<string, string>;
    const cfg = (v?: string) =>
      configFromEnv((k) => (k === "TV_REFRESH_ENABLED" ? v : base[k])).tvRefreshEnabled;
    expect(cfg()).toBeUndefined();
    expect(cfg("false")).toBeUndefined();
    expect(cfg("1")).toBeUndefined();
    expect(cfg("true")).toBe(true);
    expect(cfg(" TRUE ")).toBe(true);
  });
});
