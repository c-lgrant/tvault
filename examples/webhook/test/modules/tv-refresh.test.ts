// Tests for /v1/refresh (tvRefresh.ts) — TV-mediated refresh, HMAC-authenticated.
//
// Security contract:
//   - Missing or tampered HMAC → 401
//   - action "get" → returns decrypted refresh token (in-transit only)
//   - action "update" → persists new tokens, does NOT echo the plaintext back
//   - Unknown action → 400

import { describe, expect, it } from "vitest";
import { createApp } from "../../src/core/app.ts";
import { tvRefreshModule } from "../../src/modules/tvRefresh.ts";
import { buildEncryptedTokenDocument } from "../../src/core/protocol/tokendoc.ts";
import { computeRequestSignature } from "../../src/core/protocol/hmac.ts";
import { utf8 } from "../../src/core/crypto/encoding.ts";
import { makeContext } from "../conformance/_harness.ts";

const hmac = crypto.getRandomValues(new Uint8Array(32)) as Uint8Array<ArrayBuffer>;
const encKey = crypto.getRandomValues(new Uint8Array(32)) as Uint8Array<ArrayBuffer>;

// Deterministic, collision-free request IDs for the replay guard. A counter
// avoids Math.random()'s nondeterminism and tiny chance of a rare collision
// causing a spurious replay-guard failure.
let requestIdCounter = 0;

/** Build valid HMAC auth headers for a given body string. */
async function authHeaders(body: string): Promise<Record<string, string>> {
  const ts = String(Math.floor(Date.now() / 1000));
  const sig = await computeRequestSignature(hmac, ts, utf8(body));
  return {
    "content-type": "application/json",
    "X-TokenVault-Signature": `sha256=${sig}`,
    "X-TokenVault-Timestamp": ts,
    "X-TokenVault-Request-Id": `req_${++requestIdCounter}`,
  };
}

/** POST /v1/refresh with body and correct HMAC. */
async function callRefresh(
  app: ReturnType<typeof createApp>,
  bodyObj: Record<string, unknown>,
  tamperSig = false,
) {
  const body = JSON.stringify(bodyObj);
  const headers = await authHeaders(body);
  if (tamperSig) {
    headers["X-TokenVault-Signature"] = "sha256=deadbeef";
  }
  return app.request("https://wh.example/v1/refresh", {
    method: "POST",
    headers,
    body,
  });
}

describe("/v1/refresh — HMAC authentication", () => {
  it("missing signature header → 401", async () => {
    const ctx = makeContext({ hmacSecret: hmac, encryptionKey: encKey });
    const app = createApp(ctx, [tvRefreshModule()]);

    const res = await app.request("https://wh.example/v1/refresh", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ action: "get", service: "github", requestId: "req_1" }),
    });

    expect(res.status).toBe(401);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("auth_failed");
  });

  it("tampered signature → 401", async () => {
    const ctx = makeContext({ hmacSecret: hmac, encryptionKey: encKey });
    const app = createApp(ctx, [tvRefreshModule()]);

    const res = await callRefresh(
      app,
      { action: "get", service: "github", requestId: "req_tampered" },
      true, // tamper the sig
    );

    expect(res.status).toBe(401);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("auth_failed");
  });
});

describe("/v1/refresh — action:get", () => {
  it("returns the decrypted refresh token under valid HMAC", async () => {
    const ctx = makeContext({ hmacSecret: hmac, encryptionKey: encKey });
    const app = createApp(ctx, [tvRefreshModule()]);

    // Seed a token with an encrypted refresh token.
    const doc = await buildEncryptedTokenDocument(
      encKey,
      "access-tok",
      "refresh-tok-secret",
      { serviceName: "github" },
    );
    await ctx.storage.set("tokens", "github", doc);

    const res = await callRefresh(app, { action: "get", service: "github" });

    expect(res.status).toBe(200);
    const body = (await res.json()) as { status: string; refreshToken: string };
    expect(body.status).toBe("ok");
    // The refresh token is returned in-transit to TV for its own OAuth call.
    expect(body.refreshToken).toBe("refresh-tok-secret");
  });

  it("get returns no_refresh_token when none is stored", async () => {
    const ctx = makeContext({ hmacSecret: hmac, encryptionKey: encKey });
    const app = createApp(ctx, [tvRefreshModule()]);

    // Store a token with no refresh token.
    const doc = await buildEncryptedTokenDocument(encKey, "access-only", null, {
      serviceName: "github",
    });
    await ctx.storage.set("tokens", "github", doc);

    const res = await callRefresh(app, { action: "get", service: "github" });

    expect(res.status).toBe(200);
    const body = (await res.json()) as { status: string };
    expect(body.status).toBe("no_refresh_token");
  });
});

describe("/v1/refresh — action:update", () => {
  it("persists new tokens and does NOT echo the plaintext back", async () => {
    const ctx = makeContext({ hmacSecret: hmac, encryptionKey: encKey });
    const app = createApp(ctx, [tvRefreshModule()]);

    // Seed an existing token document.
    const doc = await buildEncryptedTokenDocument(
      encKey,
      "old-access",
      "old-refresh",
      { serviceName: "github" },
    );
    await ctx.storage.set("tokens", "github", doc);

    const newAccess = "new-access-token-very-secret";
    const newRefresh = "new-refresh-token-very-secret";

    const res = await callRefresh(app, {
      action: "update",
      service: "github",
      tokens: { accessToken: newAccess, refreshToken: newRefresh },
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as { status: string };
    expect(body.status).toBe("updated");

    // The response must NOT echo the plaintext tokens back.
    const responseText = JSON.stringify(body);
    expect(responseText).not.toContain(newAccess);
    expect(responseText).not.toContain(newRefresh);
    expect(body).not.toHaveProperty("accessToken");
    expect(body).not.toHaveProperty("refreshToken");

    // The storage document must be updated (encrypted — not plaintext).
    const updated = await ctx.storage.get("tokens", "github");
    expect(updated).not.toBeNull();
    expect(JSON.stringify(updated)).not.toContain(newAccess);
    expect(JSON.stringify(updated)).not.toContain(newRefresh);
    // Encrypted format: has "fields" key.
    expect(updated).toHaveProperty("fields");
  });
});

describe("/v1/refresh — unknown action", () => {
  it("unknown action → 400 invalid_request", async () => {
    const ctx = makeContext({ hmacSecret: hmac, encryptionKey: encKey });
    const app = createApp(ctx, [tvRefreshModule()]);

    const res = await callRefresh(app, { action: "delete", service: "github" });

    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("invalid_request");
  });
});
