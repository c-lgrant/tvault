// GET / is the first URL a new user opens after the Deploy-to-Cloudflare
// button finishes. It must report this worker's own state (seed configured?
// bound to Token Vault?) live, and is the only place the "seed missing" fix
// is shown.

import { describe, expect, it } from "vitest";
import { createApp } from "../../src/core/app.ts";
import { landingModule } from "../../src/modules/landing.ts";
import { seedDerivedSecrets } from "../../src/adapters/secrets/seedDerived.ts";
import { markBound } from "../../src/modules/bindState.ts";
import { makeContext } from "../conformance/_harness.ts";

const secret = crypto.getRandomValues(new Uint8Array(32)) as Uint8Array<ArrayBuffer>;
const HOST = { "x-forwarded-host": "wh.example" };

async function root(
  ctx: ReturnType<typeof makeContext>,
  query = "",
): Promise<{ status: number; html: string }> {
  const app = createApp(ctx, [landingModule()]);
  const res = await app.request(`https://wh.example/${query}`, { headers: HOST });
  return { status: res.status, html: await res.text() };
}

describe("landing page — seed missing", () => {
  it("reports the seed as not set, with the fix inline, and no enabled Connect link", async () => {
    const ctx = makeContext({ hmacSecret: secret });
    ctx.secrets = seedDerivedSecrets(undefined); // no TV_WEBHOOK_SEED
    const { status, html } = await root(ctx);

    expect(status).toBe(200);
    expect(html).toContain("not set");
    expect(html).toContain("TV_WEBHOOK_SEED");
    expect(html).toContain("wrangler secret put TV_WEBHOOK_SEED");
    expect(html).not.toContain('href="/bind"');
    expect(html).toContain("<!-- tv-seed:unset -->");
    expect(html).not.toContain('href="/bind?');
  });
});

describe("landing page — seed set, not yet bound", () => {
  it("shows the seed as set and a Connect link to /bind", async () => {
    const ctx = makeContext({ hmacSecret: secret });
    ctx.secrets = seedDerivedSecrets("a".repeat(64));
    const { status, html } = await root(ctx);

    expect(status).toBe(200);
    expect(html).toContain("Seed");
    expect(html).toContain("set");
    expect(html).toContain("not yet");
    expect(html).toContain('href="/bind?tv=');
    expect(html).not.toContain("tv-seed:unset");
    expect(html).toContain("Binding to: <code>https://tokenvault.test</code>");
  });

  it("forwards a ?tv= override from / to /bind", async () => {
    const ctx = makeContext({ hmacSecret: secret });
    ctx.secrets = seedDerivedSecrets("a".repeat(64));
    const { html } = await root(ctx, "?tv=https%3A%2F%2Ftokenvault.one");

    expect(html).toContain('href="/bind?tv=https%3A%2F%2Ftokenvault.one"');
    expect(html).toContain("Binding to: <code>https://tokenvault.one</code>");
  });
});

describe("landing page — bound", () => {
  it("shows 'bound to' the configured frontend and an Open Token Vault link", async () => {
    const ctx = makeContext({ hmacSecret: secret });
    ctx.secrets = seedDerivedSecrets("a".repeat(64));
    await markBound(ctx.storage);
    const { status, html } = await root(ctx);

    expect(status).toBe(200);
    expect(html).toContain("bound to <code>https://tokenvault.test</code>");
    expect(html).toContain('href="https://tokenvault.test"');
    expect(html).toContain("Open Token Vault");
    expect(html).not.toContain('href="/bind"');
    // Disconnecting in Token Vault never unbinds this webhook (vault.py leaves
    // the webhook out of scope) — the copy must not claim otherwise.
    expect(html).not.toContain("disconnecting this webhook there first");
  });

  it("says re-bind is permanently sealed when no TV_ADMIN_SECRET is configured", async () => {
    const ctx = makeContext({ hmacSecret: secret }); // no adminSecret
    ctx.secrets = seedDerivedSecrets("a".repeat(64));
    await markBound(ctx.storage);
    const { html } = await root(ctx);

    expect(html).toContain("permanently sealed");
    expect(html).toContain("TV_ADMIN_SECRET");
  });

  it("says re-bind needs the admin secret header when TV_ADMIN_SECRET is configured", async () => {
    const ctx = makeContext({ hmacSecret: secret, adminSecret: "test-admin" });
    ctx.secrets = seedDerivedSecrets("a".repeat(64));
    await markBound(ctx.storage);
    const { html } = await root(ctx);

    expect(html).toContain("x-tv-admin-secret");
    expect(html).not.toContain("permanently sealed");
  });
});

describe("landing page — response hygiene", () => {
  it("is never cached", async () => {
    const ctx = makeContext({ hmacSecret: secret });
    ctx.secrets = seedDerivedSecrets("a".repeat(64));
    const app = createApp(ctx, [landingModule()]);
    const res = await app.request("https://wh.example/", { headers: HOST });
    expect(res.headers.get("cache-control")).toBe("no-store");
  });
});
