// The bind page resolves which Token Vault frontend to hand the one-time code
// to. A `tv` query param lets the launching instance (dev/prod/self-host) point
// the webhook back at itself, but it is constrained to an https origin (http
// only for localhost) and shown on the page; anything else falls back to the
// configured TOKENVAULT_FRONTEND_URL. The chosen origin must appear in the
// register URL so TV's /vault/webhook-bind receives the code.

import { describe, expect, it } from "vitest";
import { createApp } from "../../src/core/app.ts";
import { exchangeModule } from "../../src/modules/exchange.ts";
import { makeContext } from "../conformance/_harness.ts";

const secret = crypto.getRandomValues(new Uint8Array(32)) as Uint8Array<ArrayBuffer>;

async function bindHtml(query = ""): Promise<string> {
  const ctx = makeContext({ hmacSecret: secret }); // tokenvaultFrontendUrl = https://tokenvault.test
  const app = createApp(ctx, [exchangeModule()]);
  const res = await app.request(`https://wh.example/bind${query}`, {
    headers: { "x-forwarded-host": "wh.example" },
  });
  expect(res.status).toBe(200);
  return res.text();
}

describe("bind page frontend resolution", () => {
  it("defaults to the configured frontend when no tv param is given", async () => {
    const html = await bindHtml();
    expect(html).toContain("https://tokenvault.test/vault/webhook-bind");
    expect(html).toContain("Binding to: <code>https://tokenvault.test</code>");
  });

  it("honors an https tv param (launching instance points the webhook back)", async () => {
    const html = await bindHtml("?tv=https%3A%2F%2Ftokenvault.one");
    expect(html).toContain("https://tokenvault.one/vault/webhook-bind");
    expect(html).toContain("Binding to: <code>https://tokenvault.one</code>");
    expect(html).not.toContain("tokenvault.test/vault/webhook-bind");
  });

  it("rejects a non-localhost http tv param and falls back to the default", async () => {
    const html = await bindHtml("?tv=http%3A%2F%2Fevil.example");
    expect(html).toContain("https://tokenvault.test/vault/webhook-bind");
    expect(html).not.toContain("evil.example");
  });

  it("rejects a malformed tv param and falls back to the default", async () => {
    const html = await bindHtml("?tv=not-a-url");
    expect(html).toContain("https://tokenvault.test/vault/webhook-bind");
  });
});
