// Phase 5 module behaviour: the TOTP RFC 6238 vector (proves the WebCrypto
// reimplementation matches pyotp), the credential interceptor pipeline, GCP SA
// detection, and the refresh-notify local-secret guard (the deliberate
// divergence — a hint-supplied client secret must never be used).

import { describe, expect, it, vi } from "vitest";
import { createApp } from "../../src/core/app.ts";
import { credentialModule } from "../../src/modules/credential.ts";
import { totpModule, generateTotpCode } from "../../src/modules/interceptors/totp.ts";
import { gcpSaModule, isGcpServiceAccount } from "../../src/modules/interceptors/gcpSa.ts";
import { refreshNotifyModule } from "../../src/modules/refreshNotify.ts";
import { buildEncryptedTokenDocument } from "../../src/core/protocol/tokendoc.ts";
import { signTicket } from "../../src/core/protocol/tickets.ts";
import { computeRequestSignature } from "../../src/core/protocol/hmac.ts";
import { base64UrlDecode, fromUtf8, utf8 } from "../../src/core/crypto/encoding.ts";
import type { RuntimeContext } from "../../src/runtime/context.ts";
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

// FIX 3: GCP SA interceptor must never use an agent-supplied ?scopes= param.
describe("GCP SA interceptor — scope escalation prevention (FIX 3)", () => {
  const DEFAULT_SCOPES = [
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/cloud-billing.readonly",
  ];

  it("?scopes=<elevated> does not widen the minted GCP scope beyond DEFAULT_SCOPES", async () => {
    // Generate a real RSA-2048 key so the JWT signing step succeeds.
    const { privateKey } = await crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
      },
      true,
      ["sign"],
    );
    const pkcs8Bytes = new Uint8Array(await crypto.subtle.exportKey("pkcs8", privateKey));
    const pemB64 = btoa(String.fromCharCode(...pkcs8Bytes));
    const pem = `-----BEGIN PRIVATE KEY-----\n${pemB64.match(/.{1,64}/g)!.join("\n")}\n-----END PRIVATE KEY-----\n`;

    const fakeSa = JSON.stringify({
      type: "service_account",
      private_key: pem,
      client_email: "test@proj.iam.gserviceaccount.com",
      token_uri: "https://oauth2.googleapis.com/token",
    });

    let capturedScope = "";
    vi.stubGlobal(
      "fetch",
      async (_input: unknown, init: { body?: string } | undefined) => {
        // The body is URLSearchParams: grant_type=...&assertion=<jwt>
        const params = new URLSearchParams(init?.body ?? "");
        const assertion = params.get("assertion") ?? "";
        // JWT = base64url(header).base64url(claims).base64url(sig)
        const claimsB64 = assertion.split(".")[1] ?? "";
        if (claimsB64) {
          try {
            const claims = JSON.parse(fromUtf8(base64UrlDecode(claimsB64))) as { scope?: string };
            capturedScope = claims.scope ?? "";
          } catch {
            /* ignore */
          }
        }
        return new Response(
          JSON.stringify({ access_token: "default-scoped-token", expires_in: 3600 }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      },
    );

    try {
      const interceptor = gcpSaModule().interceptor!;
      // Use a unique service name to avoid hitting the in-isolate token cache.
      const svc = `gcp-scope-fix3-${crypto.randomUUID()}`;
      // Agent supplies an elevated IAM scope — this must be ignored.
      const query = new URLSearchParams(
        "scopes=https://www.googleapis.com/auth/iam.admin",
      );

      const result = await interceptor.transform({
        token: { accessToken: fakeSa },
        service: svc,
        storedDoc: {},
        query,
        ctx: {} as RuntimeContext,
      });

      // The minted token came back from our mock, proving the fetch was called.
      expect((result as { accessToken: string }).accessToken).toBe("default-scoped-token");

      // The scope sent to Google must match DEFAULT_SCOPES exactly — the
      // elevated "iam.admin" scope must NOT be present.
      expect(capturedScope).not.toContain("iam.admin");
      expect(DEFAULT_SCOPES.every((s) => capturedScope.includes(s))).toBe(true);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
