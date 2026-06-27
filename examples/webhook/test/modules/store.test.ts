// Negative and positive tests for /v1/store (store.ts).
// The endpoint is ticket-authenticated; the IP/origin denylist runs first.

import { describe, expect, it } from "vitest";
import { createApp } from "../../src/core/app.ts";
import { storeModule } from "../../src/modules/store.ts";
import { signTicket } from "../../src/core/protocol/tickets.ts";
import type { TicketPayload } from "../../src/core/protocol/types.ts";
import { makeContext } from "../conformance/_harness.ts";

const hmac = crypto.getRandomValues(new Uint8Array(32)) as Uint8Array<ArrayBuffer>;
const wrongHmac = crypto.getRandomValues(new Uint8Array(32)) as Uint8Array<ArrayBuffer>;

function storePayload(overrides: Partial<TicketPayload> = {}): TicketPayload {
  return {
    sub: "user_test",
    svc: "github",
    pur: "store",
    iat: 1700000000,
    exp: 9999999999,
    nonce: crypto.randomUUID().replace(/-/g, ""),
    ...overrides,
  };
}

function postStore(
  app: ReturnType<typeof createApp>,
  ticket: string,
  service = "github",
  tokenData: Record<string, unknown> = { accessToken: "tok123" },
) {
  return app.request("https://wh.example/v1/store", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ticket, service, tokenData }),
  });
}

describe("/v1/store — ticket auth", () => {
  it("forged ticket (wrong signing key) → 401 ticket_invalid", async () => {
    const ctx = makeContext({ hmacSecret: hmac });
    const app = createApp(ctx, [storeModule()]);

    // Signed with the wrong key — the webhook must reject this.
    const forged = await signTicket(wrongHmac, storePayload());
    const res = await postStore(app, forged);

    expect(res.status).toBe(401);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("ticket_invalid");
    expect(body).not.toHaveProperty("meta");
  });

  it("wrong ticket purpose (agent_credential) → 401 ticket_invalid", async () => {
    const ctx = makeContext({ hmacSecret: hmac });
    const app = createApp(ctx, [storeModule()]);

    const wrongPurpose = await signTicket(hmac, storePayload({ pur: "agent_credential" }));
    const res = await postStore(app, wrongPurpose);

    expect(res.status).toBe(401);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("ticket_invalid");
  });

  it("service name mismatch (ticket.svc ≠ request service) → 401 ticket_invalid", async () => {
    const ctx = makeContext({ hmacSecret: hmac });
    const app = createApp(ctx, [storeModule()]);

    // Ticket is for "github" but the request claims "google"
    const mismatch = await signTicket(hmac, storePayload({ svc: "github" }));
    const res = await postStore(app, mismatch, "google");

    expect(res.status).toBe(401);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("ticket_invalid");
  });

  it("valid pur:store ticket → 200, stores document, returns meta not credential", async () => {
    const ctx = makeContext({ hmacSecret: hmac });
    const app = createApp(ctx, [storeModule()]);

    const valid = await signTicket(hmac, storePayload());
    const tokenData = {
      accessToken: "super-secret-access-token",
      refreshToken: "super-secret-refresh-token",
      tokenType: "oauth",
      scope: "repo",
    };
    const res = await postStore(app, valid, "github", tokenData);

    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      status: string;
      service: string;
      meta: Record<string, unknown>;
    };

    // Status and service name must be present.
    expect(body.status).toBe("stored");
    expect(body.service).toBe("github");

    // Meta is returned (public / non-sensitive fields).
    expect(body.meta).toBeDefined();
    expect(body.meta.serviceName).toBe("github");
    expect(body.meta.scope).toBe("repo");

    // The raw credential fields must NOT appear in the response.
    expect(body).not.toHaveProperty("accessToken");
    expect(body).not.toHaveProperty("refreshToken");
    expect(body.meta).not.toHaveProperty("accessToken");
    expect(body.meta).not.toHaveProperty("refreshToken");
    expect(JSON.stringify(body)).not.toContain("super-secret-access-token");
    expect(JSON.stringify(body)).not.toContain("super-secret-refresh-token");

    // The token is actually stored (encrypted) in storage.
    const stored = await ctx.storage.get("tokens", "github");
    expect(stored).not.toBeNull();
    // Encrypted document format: has "fields" but not the plaintext credential.
    expect(stored).toHaveProperty("fields");
    expect(JSON.stringify(stored)).not.toContain("super-secret-access-token");
  });
});
