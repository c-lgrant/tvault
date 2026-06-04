// Phase 5 module behaviour: the TOTP RFC 6238 vector (proves the WebCrypto
// reimplementation matches pyotp), the credential interceptor pipeline, GCP SA
// detection, and the refresh-notify local-secret guard (the deliberate
// divergence — a hint-supplied client secret must never be used).

import { describe, expect, it } from "vitest";
import { createApp } from "../../src/core/app.ts";
import { credentialModule } from "../../src/modules/credential.ts";
import { totpModule, generateTotpCode } from "../../src/modules/interceptors/totp.ts";
import { gcpSaModule, isGcpServiceAccount } from "../../src/modules/interceptors/gcpSa.ts";
import { refreshNotifyModule } from "../../src/modules/refreshNotify.ts";
import { buildEncryptedTokenDocument } from "../../src/core/protocol/tokendoc.ts";
import { signTicket } from "../../src/core/protocol/tickets.ts";
import { computeRequestSignature } from "../../src/core/protocol/hmac.ts";
import { utf8 } from "../../src/core/crypto/encoding.ts";
import type { TicketPayload } from "../../src/core/protocol/types.ts";
import { makeContext } from "../conformance/_harness.ts";

// RFC 6238 Appendix B: ASCII secret "12345678901234567890" → base32, SHA1,
// 8 digits, T=59s ⇒ 94287082.
const RFC_SECRET_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

function ticket(overrides: Partial<TicketPayload> = {}): TicketPayload {
  return {
    sub: "user_test",
    svc: "svc",
    pur: "agent_credential",
    iat: 1700000000,
    exp: 9999999999,
    nonce: crypto.randomUUID().replace(/-/g, ""),
    ...overrides,
  };
}

describe("TOTP (RFC 6238 vector)", () => {
  it("generates the canonical 8-digit code at T=59s", async () => {
    const res = await generateTotpCode(
      RFC_SECRET_B32,
      { totpAlgorithm: "SHA1", totpDigits: 8, totpPeriod: 30 },
      {},
      59_000,
    );
    expect(res.code).toBe("94287082");
    expect(res.digits).toBe(8);
    expect(res.period).toBe(30);
  });
});

describe("credential interceptor pipeline (TOTP)", () => {
  it("returns a freshly generated code instead of the stored secret", async () => {
    const key = crypto.getRandomValues(new Uint8Array(32)) as Uint8Array<ArrayBuffer>;
    const hmac = crypto.getRandomValues(new Uint8Array(32)) as Uint8Array<ArrayBuffer>;
    const ctx = makeContext({ hmacSecret: hmac, encryptionKey: key });

    const doc = await buildEncryptedTokenDocument(key, null, null, { tokenType: "TOTP", serviceName: "totp-svc" }, {
      totpSecret: RFC_SECRET_B32,
    });
    await ctx.storage.set("tokens", "totp-svc", doc);

    const app = createApp(ctx, [credentialModule(), totpModule()]);
    const t = await signTicket(hmac, ticket({ svc: "totp-svc" }));
    const res = await app.request(
      `/v1/credential?ticket=${encodeURIComponent(t)}&service=totp-svc`,
      { headers: { "x-forwarded-for": "8.8.8.8" } },
    );

    expect(res.status).toBe(200);
    const json = (await res.json()) as { token: Record<string, unknown> };
    expect(json.token.totpGenerated).toBe(true);
    expect(json.token.tokenType).toBe("TOTP");
    expect(String(json.token.accessToken)).toMatch(/^\d{6}$/);
    // The raw secret must never be returned.
    expect(json.token).not.toHaveProperty("totpSecret");
  });
});

describe("GCP SA detection", () => {
  it("recognises a service-account JSON key", () => {
    const sa = JSON.stringify({
      type: "service_account",
      private_key: "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n",
      client_email: "svc@proj.iam.gserviceaccount.com",
    });
    expect(isGcpServiceAccount(sa)).toBe(true);
    expect(isGcpServiceAccount("not json")).toBe(false);
    expect(isGcpServiceAccount(JSON.stringify({ type: "user" }))).toBe(false);
  });

  it("registers as a transparent interceptor with no capability", () => {
    const m = gcpSaModule();
    expect(m.capability).toBeUndefined();
    expect(m.interceptor?.name).toBe("gcp-sa");
  });
});

describe("refresh-notify local-secret guard", () => {
  it("ignores a hint-supplied client secret and only acknowledges", async () => {
    const key = crypto.getRandomValues(new Uint8Array(32)) as Uint8Array<ArrayBuffer>;
    const hmac = crypto.getRandomValues(new Uint8Array(32)) as Uint8Array<ArrayBuffer>;
    const ctx = makeContext({ hmacSecret: hmac, encryptionKey: key }); // no oauthProviders

    const doc = await buildEncryptedTokenDocument(key, "old-access", "old-refresh", { serviceName: "gh" });
    await ctx.storage.set("tokens", "gh", doc);

    const app = createApp(ctx, [refreshNotifyModule()]);

    const bodyObj = {
      requestId: "req_1",
      service: "gh",
      refreshHint: {
        provider: "github",
        tokenUrl: "https://example.invalid/token",
        clientId: "cid",
        clientSecret: "SHOULD-BE-IGNORED", // hint secret — must NOT be trusted
      },
    };
    const body = JSON.stringify(bodyObj);
    const ts = String(Math.floor(Date.now() / 1000));
    const sig = await computeRequestSignature(hmac, ts, utf8(body));

    const res = await app.request("/v1/refresh-notify", {
      method: "POST",
      body,
      headers: {
        "content-type": "application/json",
        "X-TokenVault-Signature": `sha256=${sig}`,
        "X-TokenVault-Timestamp": ts,
        "X-TokenVault-Request-Id": "req_1",
      },
    });

    expect(res.status).toBe(200);
    const json = (await res.json()) as { status: string };
    // No local provider creds → acknowledged. If the hint secret were trusted,
    // it would instead attempt the (failing) network refresh.
    expect(json.status).toBe("acknowledged");
  });
});
