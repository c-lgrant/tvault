// The bind page resolves which Token Vault frontend to hand the one-time code
// to. A `tv` query param lets the launching instance (dev/prod/self-host) point
// the webhook back at itself, but it is constrained to an https origin (http
// only for localhost) and shown on the page; anything else falls back to the
// configured TOKENVAULT_FRONTEND_URL. The chosen origin must appear in the
// register URL so TV's /vault/webhook-bind receives the code.

import { describe, expect, it } from "vitest";
import { createApp } from "../../src/core/app.ts";
import { exchangeModule } from "../../src/modules/exchange.ts";
import { seedDerivedSecrets } from "../../src/adapters/secrets/seedDerived.ts";
import { makeContext } from "../conformance/_harness.ts";

const secret = crypto.getRandomValues(new Uint8Array(32)) as Uint8Array<ArrayBuffer>;

const HOST = { "x-forwarded-host": "wh.example" };
const JSON_HDR = { "content-type": "application/json", ...HOST };

async function issueCode(app: ReturnType<typeof createApp>): Promise<string> {
  const res = await app.request("https://wh.example/v1/register-url", { headers: HOST });
  expect(res.status).toBe(200);
  const { code } = (await res.json()) as { code: string };
  return code;
}

function exchange(app: ReturnType<typeof createApp>, code: string) {
  return app.request("https://wh.example/v1/exchange", {
    method: "POST",
    headers: JSON_HDR,
    body: JSON.stringify({ code }),
  });
}

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

describe("bind code exchange — durable across isolates", () => {
  // The Workers bug: /bind issues a code on one isolate, TV calls /v1/exchange on
  // another. Two apps sharing one storage model that — the second must consume the
  // code the first issued. (With the old in-memory map this failed → "code expired".)
  it("a code issued on one app instance is consumable on another sharing storage", async () => {
    const ctx = makeContext({ hmacSecret: secret });
    const issuer = createApp(ctx, [exchangeModule()]); // "isolate A"
    const consumer = createApp(ctx, [exchangeModule()]); // "isolate B" — same storage

    const code = await issueCode(issuer);
    const res = await exchange(consumer, code);

    expect(res.status).toBe(200);
    const data = (await res.json()) as { hmacSecret: string };
    expect(typeof data.hmacSecret).toBe("string");
    expect(data.hmacSecret.length).toBeGreaterThan(0);
  });

  it("a code is single-use (second exchange is rejected)", async () => {
    const ctx = makeContext({ hmacSecret: secret });
    const app = createApp(ctx, [exchangeModule()]);

    const code = await issueCode(app);
    expect((await exchange(app, code)).status).toBe(200);
    expect((await exchange(app, code)).status).toBe(410);
  });

  it("an unknown code is rejected", async () => {
    const ctx = makeContext({ hmacSecret: secret });
    const app = createApp(ctx, [exchangeModule()]);
    expect((await exchange(app, "never-issued")).status).toBe(410);
  });
});

describe("bind page — setup required when no seed", () => {
  it("renders the seed-setup page (503) instead of failing opaquely", async () => {
    const ctx = makeContext({ hmacSecret: secret });
    ctx.secrets = seedDerivedSecrets(undefined); // unconfigured: no TV_WEBHOOK_SEED
    const app = createApp(ctx, [exchangeModule()]);

    const res = await app.request("https://wh.example/bind", { headers: HOST });
    expect(res.status).toBe(503);
    const html = await res.text();
    expect(html).toContain("Setup required");
    expect(html).toContain("TV_WEBHOOK_SEED");
    expect(html).not.toContain("Connect to Token Vault</a>"); // no bind button yet
  });

  it("deep-links to the worker's dashboard settings and bakes --name for a *.workers.dev host", async () => {
    const ctx = makeContext({ hmacSecret: secret });
    ctx.secrets = seedDerivedSecrets(undefined);
    const app = createApp(ctx, [exchangeModule()]);

    const res = await app.request("https://tv-webhook.acme.workers.dev/bind", {
      headers: { "x-forwarded-host": "tv-webhook.acme.workers.dev" },
    });
    expect(res.status).toBe(503);
    const html = await res.text();
    // worker name derived from the host → targeted deep link + --name flag
    expect(html).toContain(
      "dash.cloudflare.com/?to=/:account/workers/services/view/tv-webhook/production/settings",
    );
    expect(html).toContain("npx wrangler secret put TV_WEBHOOK_SEED --name tv-webhook");
  });

  it("falls back to the Workers & Pages list when the host is not *.workers.dev", async () => {
    const ctx = makeContext({ hmacSecret: secret });
    ctx.secrets = seedDerivedSecrets(undefined);
    const app = createApp(ctx, [exchangeModule()]);

    const res = await app.request("https://wh.example/bind", { headers: HOST });
    expect(res.status).toBe(503);
    const html = await res.text();
    expect(html).toContain("dash.cloudflare.com/?to=/:account/workers-and-pages");
    // unknown name → the CLI command carries no flag (prose still suggests --name)
    expect(html).toContain("put TV_WEBHOOK_SEED</pre>");
  });
});

describe("seed source — Workers Secret only", () => {
  it("a TV_WEBHOOK_SEED seed configures the webhook → bind page with the hardened note", async () => {
    const ctx = makeContext({ hmacSecret: secret });
    ctx.secrets = seedDerivedSecrets("a".repeat(64)); // env Secret present → configured
    const app = createApp(ctx, [exchangeModule()]);

    const bind = await app.request("https://wh.example/bind", { headers: HOST });
    expect(bind.status).toBe(200); // configured → bind page, not setup
    const html = await bind.text();
    expect(html).toContain("Connect to Token Vault");
    expect(html).toContain("Workers Secret (hardened)");
    expect(html).not.toContain("stored in KV"); // no KV seed path anymore
  });

  it("the setup page no longer offers a KV generate-&-save path", async () => {
    const ctx = makeContext({ hmacSecret: secret });
    ctx.secrets = seedDerivedSecrets(undefined); // unconfigured
    const app = createApp(ctx, [exchangeModule()]);
    const html = await (await app.request("https://wh.example/bind", { headers: HOST })).text();
    expect(html).not.toContain("Generate &amp; save seed");
    expect(html).not.toContain("/bind/init-seed");
  });

  it("the /bind/init-seed route is gone (404)", async () => {
    const ctx = makeContext({ hmacSecret: secret });
    ctx.secrets = seedDerivedSecrets(undefined);
    const app = createApp(ctx, [exchangeModule()]);
    const res = await app.request("https://wh.example/bind/init-seed", { method: "POST", headers: HOST });
    expect(res.status).toBe(404);
  });
});
