// The two adversarial probes TV runs against a webhook (vault.py:838-965):
//   1. credential_fake_ticket      — forged ticket (wrong key) MUST be rejected
//   2. credential_real_ticket_wrong_ip — real ticket from TV's IP MUST be rejected
// Plus a positive control proving the denylist lets allowed IPs through.

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { base64Decode } from "../../src/core/crypto/encoding.ts";
import { createApp } from "../../src/core/app.ts";
import { credentialModule } from "../../src/modules/credential.ts";
import { signTicket } from "../../src/core/protocol/tickets.ts";
import type { TicketPayload } from "../../src/core/protocol/types.ts";
import { makeContext } from "./_harness.ts";

const fx = JSON.parse(readFileSync(new URL("./fixtures.json", import.meta.url), "utf-8")) as {
  hmacSecretB64: string;
  wrongSecretB64: string;
};
const secret = base64Decode(fx.hmacSecretB64);
const wrongSecret = base64Decode(fx.wrongSecretB64);

function validPayload(): TicketPayload {
  return {
    sub: "user_test",
    svc: "github",
    pur: "agent_credential",
    iat: 1700000000,
    exp: 9999999999,
    nonce: crypto.randomUUID().replace(/-/g, ""),
  };
}

function credentialUrl(ticket: string): string {
  return `/v1/credential?ticket=${encodeURIComponent(ticket)}&service=github`;
}

describe("adversarial probes", () => {
  it("rejects a credential ticket signed with the WRONG key", async () => {
    const ctx = makeContext({ hmacSecret: secret });
    const app = createApp(ctx, [credentialModule()]);

    const forged = await signTicket(wrongSecret, validPayload());
    const res = await app.request(credentialUrl(forged));

    expect([401, 403]).toContain(res.status);
    expect(await res.json()).not.toHaveProperty("token");
  });

  it("rejects a REAL ticket replayed from a denied IP", async () => {
    const ctx = makeContext({ hmacSecret: secret, denyIps: ["10.9.9.9"] });
    const app = createApp(ctx, [credentialModule()]);

    const real = await signTicket(secret, validPayload());
    const res = await app.request(credentialUrl(real), {
      headers: { "x-forwarded-for": "10.9.9.9" },
    });

    expect(res.status).toBe(403);
    expect(await res.json()).not.toHaveProperty("token");
  });

  it("lets a real ticket from an allowed IP through to credential logic (control)", async () => {
    const ctx = makeContext({ hmacSecret: secret, denyIps: ["10.9.9.9"] });
    const app = createApp(ctx, [credentialModule()]);

    const real = await signTicket(secret, validPayload());
    const res = await app.request(credentialUrl(real), {
      headers: { "x-forwarded-for": "8.8.8.8" },
    });

    // Valid ticket, allowed IP, but no token stored → 404 token_not_found,
    // which proves the denylist did not block and the ticket verified.
    expect(res.status).toBe(404);
  });
});
