// Security invariants that must hold regardless of wire-compat: ticket expiry
// is enforced, malformed tickets are rejected, the proxy refuses unauthenticated
// (no-HMAC) callers, and the credential denylist also matches the CDN client-IP
// header (cf-connecting-ip), not just x-forwarded-for.

import { describe, expect, it } from "vitest";
import { createApp } from "../../src/core/app.ts";
import { credentialModule } from "../../src/modules/credential.ts";
import { proxyModule } from "../../src/modules/proxy.ts";
import { signTicket, verifyTicket } from "../../src/core/protocol/tickets.ts";
import { MemoryReplayGuard } from "../../src/adapters/replay/memory.ts";
import type { TicketPayload } from "../../src/core/protocol/types.ts";
import { makeContext } from "../conformance/_harness.ts";

const secret = crypto.getRandomValues(new Uint8Array(32)) as Uint8Array<ArrayBuffer>;

function payload(overrides: Partial<TicketPayload> = {}): TicketPayload {
  return {
    sub: "u",
    svc: "github",
    pur: "agent_credential",
    iat: 1700000000,
    exp: 9999999999,
    nonce: crypto.randomUUID().replace(/-/g, ""),
    ...overrides,
  };
}

describe("ticket expiry + integrity", () => {
  it("rejects an expired ticket (exp in the past)", async () => {
    const expired = await signTicket(secret, payload({ exp: 1700000001 }));
    await expect(verifyTicket(expired, secret, new MemoryReplayGuard())).rejects.toMatchObject({
      code: "ticket_expired",
    });
  });

  it("rejects a malformed ticket", async () => {
    await expect(verifyTicket("not-a-ticket", secret, new MemoryReplayGuard())).rejects.toMatchObject({
      code: "ticket_invalid",
    });
  });

  it("treats a missing exp as expired (fail-closed)", async () => {
    // Hand-build a ticket whose payload has no exp field.
    const noExp = await signTicket(secret, { sub: "u", svc: "github", pur: "agent_credential", iat: 1, nonce: "x" } as TicketPayload);
    await expect(verifyTicket(noExp, secret, new MemoryReplayGuard())).rejects.toMatchObject({
      code: "ticket_expired",
    });
  });
});

describe("proxy authentication", () => {
  it("rejects an unauthenticated (no-HMAC) proxy call with 401", async () => {
    const ctx = makeContext({ hmacSecret: secret });
    const app = createApp(ctx, [proxyModule()]);
    const res = await app.request("/v1/proxy", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ticket: "x", service: "github", upstream: { url: "https://example.invalid" } }),
    });
    expect(res.status).toBe(401);
    expect(await res.json()).not.toHaveProperty("token");
  });
});

describe("credential denylist (CDN header)", () => {
  it("rejects a real ticket when cf-connecting-ip is the denied TV IP", async () => {
    const ctx = makeContext({ hmacSecret: secret, denyIps: ["203.0.113.7"] });
    const app = createApp(ctx, [credentialModule()]);
    const real = await signTicket(secret, payload());
    const res = await app.request(`/v1/credential?ticket=${encodeURIComponent(real)}&service=github`, {
      headers: { "cf-connecting-ip": "203.0.113.7" },
    });
    expect(res.status).toBe(403);
    expect(await res.json()).not.toHaveProperty("token");
  });
});

// FIX 4 invariants

describe("FIX 4c — ticket nonce is required", () => {
  it("rejects a ticket whose nonce field is absent", async () => {
    // Cast to bypass TypeScript's required-field check so we can test the runtime guard.
    const noNonce = await signTicket(secret, {
      sub: "u",
      svc: "github",
      pur: "agent_credential",
      iat: 1700000000,
      exp: 9999999999,
    } as unknown as Parameters<typeof signTicket>[1]);
    await expect(verifyTicket(noNonce, secret, new MemoryReplayGuard())).rejects.toMatchObject({
      code: "ticket_invalid",
    });
  });

  it("rejects a ticket whose nonce field is an empty string", async () => {
    const emptyNonce = await signTicket(secret, {
      sub: "u",
      svc: "github",
      pur: "agent_credential",
      iat: 1700000000,
      exp: 9999999999,
      nonce: "",
    } as Parameters<typeof signTicket>[1]);
    await expect(verifyTicket(emptyNonce, secret, new MemoryReplayGuard())).rejects.toMatchObject({
      code: "ticket_invalid",
    });
  });

  it("rejects a ticket whose nonce is a non-string (controlled 401, not a 500)", async () => {
    // Regression for the Copilot review: a tampered payload with a numeric nonce
    // must yield ticket_invalid, not throw downstream in checkNonce.
    const numericNonce = await signTicket(secret, {
      sub: "u",
      svc: "github",
      pur: "agent_credential",
      iat: 1700000000,
      exp: 9999999999,
      nonce: 12345,
    } as unknown as Parameters<typeof signTicket>[1]);
    await expect(verifyTicket(numericNonce, secret, new MemoryReplayGuard())).rejects.toMatchObject({
      code: "ticket_invalid",
    });
  });
});

describe("FIX 4b — browser_credential is not an accepted purpose", () => {
  it("rejects a ticket with pur=browser_credential at /v1/credential", async () => {
    const { credentialModule: cm } = await import("../../src/modules/credential.ts");
    const ctx = makeContext({ hmacSecret: secret });
    const app = createApp(ctx, [cm()]);
    const t = await signTicket(secret, {
      sub: "u",
      svc: "github",
      pur: "browser_credential",
      iat: 1700000000,
      exp: 9999999999,
      nonce: crypto.randomUUID().replace(/-/g, ""),
    });
    const res = await app.request(`/v1/credential?ticket=${encodeURIComponent(t)}&service=github`);
    expect(res.status).toBe(401);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("ticket_invalid");
  });
});

describe("FIX 4d — X-TokenVault-Request-Id is required on HMAC-auth endpoints", () => {
  it("rejects HMAC-auth requests that omit X-TokenVault-Request-Id with 401", async () => {
    const { proxyModule: pm } = await import("../../src/modules/proxy.ts");
    const ctx = makeContext({ hmacSecret: secret });
    const app = createApp(ctx, [pm()]);
    const body = JSON.stringify({
      ticket: "x",
      service: "github",
      upstream: { url: "https://example.invalid" },
    });
    const ts = String(Math.floor(Date.now() / 1000));
    // Import computeRequestSignature dynamically to keep this describe self-contained.
    const { computeRequestSignature } = await import("../../src/core/protocol/hmac.ts");
    const { utf8: u8 } = await import("../../src/core/crypto/encoding.ts");
    const sig = await computeRequestSignature(secret, ts, u8(body));
    // Valid HMAC but deliberately omit X-TokenVault-Request-Id.
    const res = await app.request("/v1/proxy", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "X-TokenVault-Signature": `sha256=${sig}`,
        "X-TokenVault-Timestamp": ts,
        // No X-TokenVault-Request-Id
      },
      body,
    });
    expect(res.status).toBe(401);
    const json = (await res.json()) as { error: string; message: string };
    expect(json.error).toBe("auth_failed");
    expect(json.message).toContain("Request-Id");
  });
});
