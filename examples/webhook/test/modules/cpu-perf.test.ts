// CPU-side behaviour: base64 decoding, single JSON parse per request, imported
// key reuse, parallel field decryption, and the GCP minted-token cache.

import { afterEach, describe, expect, it, vi } from "vitest";
import { base64Decode, base64Encode } from "../../src/core/crypto/encoding.ts";
import { decrypt, encrypt } from "../../src/core/crypto/aesgcm.ts";
import { computeRequestSignature, hmacSha256Hex } from "../../src/core/protocol/hmac.ts";
import { buildEncryptedTokenDocument, readTokenObject } from "../../src/core/protocol/tokendoc.ts";
import { createApp } from "../../src/core/app.ts";
import { storageModule } from "../../src/modules/storage.ts";
import { mintGcpAccessToken } from "../../src/modules/interceptors/gcpSa.ts";
import { utf8 } from "../../src/core/crypto/encoding.ts";
import { makeContext } from "../conformance/_harness.ts";

afterEach(() => vi.restoreAllMocks());

describe("base64Decode", () => {
  const big = crypto.getRandomValues(new Uint8Array(60_000));

  it("decodes a large canonical string exactly", () => {
    const out = base64Decode(base64Encode(big));
    expect(out.length).toBe(big.length);
    expect(Buffer.from(out).equals(Buffer.from(big))).toBe(true);
  });

  it("still rejects invalid input, large or small", () => {
    expect(() => base64Decode(`${base64Encode(big)}!`)).toThrow();
    expect(() => base64Decode("not base64!")).toThrow();
  });

  it("keeps atob's behaviour for unpadded and whitespace-wrapped input", () => {
    const enc = base64Encode(big.slice(0, 2000));
    expect(base64Decode(enc.replace(/=+$/, "")).length).toBe(2000);
    expect(base64Decode(enc.replace(/(.{76})/g, "$1\n")).length).toBe(2000);
  });
});

describe("single JSON parse", () => {
  it("parses a signed request body once for auth and handler together", async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32)) as Uint8Array<ArrayBuffer>;
    const ctx = makeContext({ hmacSecret: secret });
    const app = createApp(ctx, [storageModule()]);
    const id = crypto.randomUUID();
    const raw = JSON.stringify({ operation: "get", collection: "tokens", key: "x", attemptId: id });
    const ts = String(Math.floor(Date.now() / 1000));
    const sig = await computeRequestSignature(secret, ts, utf8(raw));

    const real = JSON.parse;
    let ofBody = 0;
    vi.spyOn(JSON, "parse").mockImplementation((text: string, ...rest: []) => {
      if (text === raw) ofBody++;
      return real(text, ...rest);
    });
    const res = await app.request("/v1/storage", {
      method: "POST",
      headers: {
        "X-TokenVault-Signature": `sha256=${sig}`,
        "X-TokenVault-Timestamp": ts,
        "X-TokenVault-Request-Id": id,
      },
      body: raw,
    });
    expect(res.status).toBe(200);
    expect(ofBody).toBe(1);
  });
});

describe("imported key reuse", () => {
  it("imports the AES and HMAC keys once per key, not once per operation", async () => {
    const spy = vi.spyOn(crypto.subtle, "importKey");
    const aes = crypto.getRandomValues(new Uint8Array(32)) as Uint8Array<ArrayBuffer>;
    const mac = crypto.getRandomValues(new Uint8Array(32)) as Uint8Array<ArrayBuffer>;
    for (let i = 0; i < 5; i++) expect(await decrypt(aes, await encrypt(aes, `v${i}`))).toBe(`v${i}`);
    for (let i = 0; i < 5; i++) await hmacSha256Hex(mac, utf8(`m${i}`));
    expect(spy).toHaveBeenCalledTimes(2);

    // A different key is a different import, and never decrypts the other's data.
    const other = crypto.getRandomValues(new Uint8Array(32)) as Uint8Array<ArrayBuffer>;
    const ct = await encrypt(aes, "secret");
    await expect(decrypt(other, ct)).rejects.toThrow(/decryption failed/);
    expect(spy).toHaveBeenCalledTimes(3);
  });
});

describe("readTokenObject", () => {
  it("decrypts every field (in parallel) and merges meta without overriding", async () => {
    const key = crypto.getRandomValues(new Uint8Array(32)) as Uint8Array<ArrayBuffer>;
    const doc = await buildEncryptedTokenDocument(key, "AT", "RT", { serviceName: "s", accessToken: "meta-must-not-win" }, { totpSecret: "SEED" });
    const tok = await readTokenObject(key, doc);
    expect(tok).toMatchObject({ accessToken: "AT", refreshToken: "RT", totpSecret: "SEED", serviceName: "s" });
    expect(Object.keys(tok).slice(0, 3)).toEqual(["accessToken", "refreshToken", "totpSecret"]);
  });
});

describe("GCP minted-token cache", () => {
  async function saKey(email: string): Promise<string> {
    const pair = await crypto.subtle.generateKey(
      { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      true,
      ["sign", "verify"],
    );
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
    const pem = `-----BEGIN PRIVATE KEY-----\n${base64Encode(pkcs8)}\n-----END PRIVATE KEY-----\n`;
    return JSON.stringify({ type: "service_account", client_email: email, private_key: pem });
  }

  it("does not serve a token minted from a key that has since been replaced", async () => {
    const oldKey = await saKey("sa@example.test");
    const newKey = await saKey("sa@example.test"); // same account, rotated key
    let n = 0;
    const fetchMock = vi.fn(async () => Response.json({ access_token: `tok-${++n}`, expires_in: 3600 }));
    vi.stubGlobal("fetch", fetchMock);

    const a = await mintGcpAccessToken(oldKey, "gcp-rotate");
    expect((await mintGcpAccessToken(oldKey, "gcp-rotate")).accessToken).toBe(a.accessToken); // cached
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const b = await mintGcpAccessToken(newKey, "gcp-rotate");
    expect(b.accessToken).not.toBe(a.accessToken);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    vi.unstubAllGlobals();
  });

  it("bounds the token request with a timeout and reports it as gcp_mint_failed", async () => {
    const key = await saKey("sb@example.test");
    let signal: AbortSignal | null | undefined;
    vi.stubGlobal("fetch", async (_u: string, init: RequestInit) => {
      signal = init.signal;
      throw new DOMException("timed out", "TimeoutError");
    });
    await expect(mintGcpAccessToken(key, "gcp-timeout")).rejects.toMatchObject({ code: "gcp_mint_failed" });
    expect(signal).toBeInstanceOf(AbortSignal);
    vi.unstubAllGlobals();
  });
});
