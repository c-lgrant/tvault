// /v1/credential gives an agent the credential but never its refresh token. A
// person's own reveal (user_reveal) still gets every field.

import { describe, expect, it } from "vitest";
import { createApp } from "../../src/core/app.ts";
import { signTicket } from "../../src/core/protocol/tickets.ts";
import { buildEncryptedTokenDocument } from "../../src/core/protocol/tokendoc.ts";
import { credentialModule } from "../../src/modules/credential.ts";
import { makeContext } from "../conformance/_harness.ts";

const SERVICE = "google";

async function fetchToken(pur: string, encrypted: boolean): Promise<Record<string, unknown>> {
  const key = crypto.getRandomValues(new Uint8Array(32)) as Uint8Array<ArrayBuffer>;
  const hmac = crypto.getRandomValues(new Uint8Array(32)) as Uint8Array<ArrayBuffer>;
  const ctx = makeContext({ hmacSecret: hmac, encryptionKey: key });
  const meta = { tokenType: "OAuth", serviceName: SERVICE, hasRefreshToken: true };
  await ctx.storage.set(
    "tokens",
    SERVICE,
    encrypted
      ? await buildEncryptedTokenDocument(key, "the-access-token", "the-refresh-token", meta)
      : { id: SERVICE, accessToken: "the-access-token", refreshToken: "the-refresh-token", ...meta },
  );

  const app = createApp(ctx, [credentialModule()]);
  const ticket = await signTicket(hmac, {
    sub: "user_test",
    svc: SERVICE,
    pur,
    iat: 1700000000,
    exp: 9999999999,
    nonce: crypto.randomUUID().replace(/-/g, ""),
  });
  const res = await app.request(
    `/v1/credential?ticket=${encodeURIComponent(ticket)}&service=${SERVICE}`,
    { headers: { "x-forwarded-for": "8.8.8.8" } },
  );
  expect(res.status).toBe(200);
  return ((await res.json()) as { token: Record<string, unknown> }).token;
}

describe("/v1/credential and the refresh token", () => {
  for (const encrypted of [true, false]) {
    const stored = encrypted ? "encrypted" : "plaintext";

    it(`an agent gets the access token and no refresh token (${stored})`, async () => {
      const token = await fetchToken("agent_credential", encrypted);
      expect(token.accessToken).toBe("the-access-token");
      expect(token).not.toHaveProperty("refreshToken");
      expect(JSON.stringify(token)).not.toContain("the-refresh-token");
    });

    it(`a person's reveal still gets the refresh token (${stored})`, async () => {
      const token = await fetchToken("user_reveal", encrypted);
      expect(token.accessToken).toBe("the-access-token");
      expect(token.refreshToken).toBe("the-refresh-token");
    });
  }
});
