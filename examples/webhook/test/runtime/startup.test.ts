import { describe, expect, it } from "vitest";
import { runStartup } from "../../src/runtime/startup.ts";
import { isBound } from "../../src/modules/bindState.ts";
import { makeContext } from "../conformance/_harness.ts";
import { CURRENT_SCHEMA_VERSION } from "../../src/migrations/index.ts";

const secret = crypto.getRandomValues(new Uint8Array(32)) as Uint8Array<ArrayBuffer>;

describe("runStartup", () => {
  it("stamps the schema version", async () => {
    const ctx = makeContext({ hmacSecret: secret });
    await runStartup(ctx);
    expect((await ctx.storage.get("meta", "schema_state"))?.version).toBe(CURRENT_SCHEMA_VERSION);
  });

  it("auto-seals a configured webhook that already has tokens", async () => {
    const ctx = makeContext({ hmacSecret: secret });
    await ctx.storage.set("tokens", "github", { tokenId: "github", serviceName: "github" });
    expect(await isBound(ctx.storage)).toBe(false);
    await runStartup(ctx);
    expect(await isBound(ctx.storage)).toBe(true);
  });

  it("leaves a fresh webhook (no tokens) unbound", async () => {
    const ctx = makeContext({ hmacSecret: secret });
    await runStartup(ctx);
    expect(await isBound(ctx.storage)).toBe(false);
  });

  it("does not disturb an already-bound webhook", async () => {
    const ctx = makeContext({ hmacSecret: secret });
    await ctx.storage.set("meta", "bind_state", { bound: true, boundAt: 1 });
    await ctx.storage.set("tokens", "github", { tokenId: "github", serviceName: "github" });
    await runStartup(ctx);
    expect(await isBound(ctx.storage)).toBe(true);
  });
});
