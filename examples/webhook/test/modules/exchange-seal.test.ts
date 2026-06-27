// Tests for the bind-state seal introduced in FIX 1:
// After the first successful /v1/exchange the setup endpoints are sealed behind
// TV_ADMIN_SECRET (x-tv-admin-secret header).
//
// Also covers FIX 2: configFromEnv must throw when TOKENVAULT_FRONTEND_URL is absent.

import { describe, expect, it } from "vitest";
import { createApp } from "../../src/core/app.ts";
import { exchangeModule } from "../../src/modules/exchange.ts";
import { isBound } from "../../src/modules/bindState.ts";
import { configFromEnv } from "../../src/runtime/config.ts";
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

function exchange(
  app: ReturnType<typeof createApp>,
  code: string,
  adminSecret?: string,
) {
  const headers: Record<string, string> = { ...JSON_HDR };
  if (adminSecret !== undefined) headers["x-tv-admin-secret"] = adminSecret;
  return app.request("https://wh.example/v1/exchange", {
    method: "POST",
    headers,
    body: JSON.stringify({ code }),
  });
}

function registerUrl(
  app: ReturnType<typeof createApp>,
  adminSecret?: string,
) {
  const headers: Record<string, string> = { ...HOST };
  if (adminSecret !== undefined) headers["x-tv-admin-secret"] = adminSecret;
  return app.request("https://wh.example/v1/register-url", { headers });
}

describe("bind seal — isBound transitions", () => {
  it("(a) first successful /v1/exchange returns 200 and marks the webhook bound", async () => {
    const ctx = makeContext({ hmacSecret: secret });
    const app = createApp(ctx, [exchangeModule()]);

    // Before first exchange, the webhook is not bound.
    expect(await isBound(ctx.storage)).toBe(false);

    const code = await issueCode(app);
    const res = await exchange(app, code);

    expect(res.status).toBe(200);
    const data = (await res.json()) as { hmacSecret: string };
    expect(typeof data.hmacSecret).toBe("string");
    expect(data.hmacSecret.length).toBeGreaterThan(0);

    // After exchange, the webhook must be marked bound.
    expect(await isBound(ctx.storage)).toBe(true);
  });

  it("(f) a failed exchange (secrets throw) does NOT seal the webhook", async () => {
    // Regression for the Copilot review: bind_state must be persisted only on a
    // fully successful exchange. If the secrets provider throws, the setup
    // endpoints must remain open so the operator can recover.
    const ctx = makeContext({ hmacSecret: secret });
    ctx.secrets = {
      isConfigured: async () => true,
      hmacSecret: async () => {
        throw new Error("seed missing");
      },
      encryptionKey: async () => secret,
      webhookId: async () => "wh_test",
      hmacSecretHash: async () => "x",
    };
    const app = createApp(ctx, [exchangeModule()]);

    const code = await issueCode(app);
    const res = await exchange(app, code);

    expect(res.status).toBeGreaterThanOrEqual(500);
    // The failed exchange must leave the webhook unbound and recoverable.
    expect(await isBound(ctx.storage)).toBe(false);
  });
});

describe("bind seal — endpoints locked after first bind", () => {
  async function setupBound(adminSecretValue?: string) {
    const ctx = makeContext({
      hmacSecret: secret,
      ...(adminSecretValue ? { adminSecret: adminSecretValue } : {}),
    });
    const app = createApp(ctx, [exchangeModule()]);

    // Perform an initial bind to put the webhook into the "bound" state.
    const code = await issueCode(app);
    const res = await exchange(app, code);
    expect(res.status).toBe(200);
    expect(await isBound(ctx.storage)).toBe(true);

    return { ctx, app };
  }

  it("(b) GET /v1/register-url with no admin secret → 403 after bound", async () => {
    const { app } = await setupBound();
    const res = await registerUrl(app);
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("forbidden");
  });

  it("(c) GET /v1/register-url with correct x-tv-admin-secret → 200", async () => {
    const { app } = await setupBound("correct-secret-value");
    const res = await registerUrl(app, "correct-secret-value");
    expect(res.status).toBe(200);
  });

  it("(d) GET /v1/register-url with wrong secret → 403", async () => {
    const { app } = await setupBound("correct-secret-value");
    const res = await registerUrl(app, "wrong-secret-value");
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("forbidden");
  });

  it("(e) POST /v1/exchange after bound with no admin secret → 403", async () => {
    const { app, ctx } = await setupBound();
    // Issue a fresh code (bypasses the guard at register-url level here because
    // we're testing exchange directly with a fabricated scenario). We'll test
    // by attempting exchange with a code against a bound webhook.
    // Since register-url is also sealed, simulate by writing a code directly.
    await ctx.storage.set("_bind_codes", "test-code", {
      exp: Date.now() + 300_000,
    });
    const res = await exchange(app, "test-code");
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("forbidden");
  });

  it("bound webhook with no adminSecret configured is fully sealed (even with a header)", async () => {
    // When TV_ADMIN_SECRET is not set, the webhook is fully sealed after bind.
    const { app, ctx } = await setupBound(/* no adminSecret */);
    await ctx.storage.set("_bind_codes", "test-code2", {
      exp: Date.now() + 300_000,
    });
    // Providing any value still fails because there's no expected secret to compare against.
    const res = await exchange(app, "test-code2", "any-value");
    expect(res.status).toBe(403);
    // The message must not imply a header can re-bind it — it's permanently sealed.
    const body = (await res.json()) as { message: string };
    expect(body.message).toContain("permanently sealed");
    expect(body.message).toContain("TV_ADMIN_SECRET");
  });
});

describe("bind seal — guardBound runs before config resolution (Copilot review)", () => {
  it("(g) /bind on a bound-but-misconfigured webhook returns 403, not the setup page", async () => {
    // A webhook that was bound and later lost its seed (isConfigured false) must
    // stay sealed: guardBound runs first, so an unauthenticated caller gets 403
    // rather than the 503 setup page (which would leak that it's re-bindable).
    const ctx = makeContext({ hmacSecret: secret });
    await ctx.storage.set("meta", "bind_state", { bound: true, boundAt: 1 });
    ctx.secrets = {
      isConfigured: async () => false,
      hmacSecret: async () => secret,
      encryptionKey: async () => secret,
      webhookId: async () => "wh_test",
      hmacSecretHash: async () => "x",
    };
    const app = createApp(ctx, [exchangeModule()]);
    const res = await app.request("https://wh.example/bind", { headers: HOST });
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("forbidden");
  });

  it("(h) /v1/register-url on a bound webhook with no resolvable URL returns 403, not 400 misconfig", async () => {
    // With no host headers resolveExternalUrl() is null. Pre-fix the handler
    // resolved the URL first and returned a 400 misconfig before the seal check,
    // leaking config state. guardBound now runs first → 403.
    const ctx = makeContext({ hmacSecret: secret });
    await ctx.storage.set("meta", "bind_state", { bound: true, boundAt: 1 });
    const app = createApp(ctx, [exchangeModule()]);
    const res = await app.request(new Request("http://localhost/v1/register-url"));
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("forbidden");
  });
});

describe("FIX 2 — configFromEnv requires TOKENVAULT_FRONTEND_URL", () => {
  it("throws when TOKENVAULT_FRONTEND_URL is absent", () => {
    expect(() =>
      configFromEnv((_key: string) => undefined),
    ).toThrow("TOKENVAULT_FRONTEND_URL is required");
  });

  it("succeeds when TOKENVAULT_FRONTEND_URL is present", () => {
    const cfg = configFromEnv((key: string) =>
      key === "TOKENVAULT_FRONTEND_URL" ? "https://tokenvault.uk" : undefined,
    );
    expect(cfg.tokenvaultFrontendUrl).toBe("https://tokenvault.uk");
  });

  it("populates adminSecret from TV_ADMIN_SECRET", () => {
    const cfg = configFromEnv((key: string) => {
      if (key === "TOKENVAULT_FRONTEND_URL") return "https://tokenvault.uk";
      if (key === "TV_ADMIN_SECRET") return "my-admin-secret";
      return undefined;
    });
    expect(cfg.adminSecret).toBe("my-admin-secret");
  });

  it("omits adminSecret when TV_ADMIN_SECRET is not set", () => {
    const cfg = configFromEnv((key: string) =>
      key === "TOKENVAULT_FRONTEND_URL" ? "https://tokenvault.uk" : undefined,
    );
    expect(cfg.adminSecret).toBeUndefined();
  });
});
