// TOTP-at-rest fix (totpUri is sensitive; legacy docs heal on read/list/migrate)
// and ticket constraints (capability `ticketConstraints`: mode + cid).

import { describe, expect, it } from "vitest";
import { createApp } from "../../src/core/app.ts";
import { allModules } from "../../src/modules/index.ts";
import { signTicket } from "../../src/core/protocol/tickets.ts";
import { computeRequestSignature } from "../../src/core/protocol/hmac.ts";
import { parseTotpUri } from "../../src/core/protocol/totpUri.ts";
import { buildEncryptedTokenDocument, readTokenObject } from "../../src/core/protocol/tokendoc.ts";
import { utf8 } from "../../src/core/crypto/encoding.ts";
import type { TicketPayload } from "../../src/core/protocol/types.ts";
import { makeContext } from "../conformance/_harness.ts";

const SEED = "JBSWY3DPEHPK3PXP";
const URI = `otpauth://totp/Acme:alice%40example.com?secret=${SEED}&issuer=Acme&algorithm=SHA256&digits=8&period=45`;

function setup() {
  const hmac = crypto.getRandomValues(new Uint8Array(32)) as Uint8Array<ArrayBuffer>;
  const key = crypto.getRandomValues(new Uint8Array(32)) as Uint8Array<ArrayBuffer>;
  const ctx = makeContext({ hmacSecret: hmac, encryptionKey: key });
  const app = createApp(ctx, allModules());
  const ticket = (o: Partial<TicketPayload>) =>
    signTicket(hmac, {
      sub: "u",
      svc: "svc",
      pur: "store",
      iat: 1700000000,
      exp: 9999999999,
      nonce: crypto.randomUUID().replace(/-/g, ""),
      ...o,
    });
  const store = async (t: string, tokenData: Record<string, unknown>, service = "svc") =>
    app.request("https://wh.example/v1/store", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ticket: t, service, tokenData }),
    });
  const credential = async (t: string, service = "svc") =>
    app.request(`https://wh.example/v1/credential?service=${service}&ticket=${encodeURIComponent(t)}`);
  const signed = async (path: string, obj: unknown) => {
    const body = JSON.stringify(obj);
    const ts = String(Math.floor(Date.now() / 1000));
    const sig = await computeRequestSignature(hmac, ts, utf8(body));
    return app.request(`https://wh.example${path}`, {
      method: "POST",
      body,
      headers: {
        "content-type": "application/json",
        "X-TokenVault-Signature": `sha256=${sig}`,
        "X-TokenVault-Timestamp": ts,
        "X-TokenVault-Request-Id": crypto.randomUUID(),
      },
    });
  };
  return { hmac, key, ctx, app, ticket, store, credential, signed };
}

async function seedLegacy(s: ReturnType<typeof setup>, service = "legacy") {
  const doc = await buildEncryptedTokenDocument(s.key, null, null, {
    serviceName: service,
    tokenType: "TOTP",
    totpUri: URI,
  });
  await s.ctx.storage.set("tokens", service, doc);
}

describe("parseTotpUri", () => {
  it("extracts seed and descriptors", () => {
    const p = parseTotpUri(URI);
    expect(p).toMatchObject({
      secret: SEED,
      issuer: "Acme",
      accountName: "alice@example.com",
      algorithm: "SHA256",
      digits: 8,
      period: 45,
    });
  });
  it("defaults algorithm/digits/period", () => {
    expect(parseTotpUri(`otpauth://totp/x?secret=${SEED}`)).toMatchObject({ algorithm: "SHA1", digits: 6, period: 30 });
  });
  it.each([
    "not a uri",
    `otpauth://hotp/x?secret=${SEED}`,
    "otpauth://totp/x",
    "otpauth://totp/x?secret=!!!",
    `otpauth://totp/x?secret=${SEED}&digits=3`,
    `otpauth://totp/x?secret=${SEED}&algorithm=MD5`,
  ])("rejects %s", (u) => {
    expect(() => parseTotpUri(u)).toThrow();
  });
});

describe("/v1/store totpUri", () => {
  it("stores the seed encrypted, descriptors in meta, never the URI", async () => {
    const s = setup();
    const res = await s.store(await s.ticket({}), { totpUri: URI });
    expect(res.status).toBe(200);
    const text = await res.text();
    expect(text).not.toContain(SEED);
    expect(text).not.toContain("otpauth");

    const doc = (await s.ctx.storage.get("tokens", "svc"))!;
    const raw = JSON.stringify(doc);
    expect(raw).not.toContain(SEED);
    expect(raw).not.toContain("otpauth");
    const meta = doc.meta as Record<string, unknown>;
    expect(meta).toMatchObject({
      tokenType: "TOTP",
      totpIssuer: "Acme",
      totpAccountName: "alice@example.com",
      totpAlgorithm: "SHA256",
      totpDigits: 8,
      totpPeriod: 45,
      hasTotpSecret: true,
    });
    expect((await readTokenObject(s.key, doc)).totpSecret).toBe(SEED);

    const cred = await s.credential(await s.ticket({ pur: "agent_credential" }));
    const out = (await cred.json()) as { token: Record<string, unknown> };
    expect(out.token.totpGenerated).toBe(true);
    expect(out.token.digits).toBe(8);
    expect(JSON.stringify(out)).not.toContain(SEED);
  });

  it("malformed totpUri -> 400", async () => {
    const s = setup();
    const res = await s.store(await s.ticket({}), { totpUri: "otpauth://totp/x?secret=%%%" });
    expect(res.status).toBe(400);
    expect(await s.ctx.storage.get("tokens", "svc")).toBeNull();
  });
});

describe("legacy totpUri migration", () => {
  it("heals on /v1/credential", async () => {
    const s = setup();
    await seedLegacy(s);
    const res = await s.credential(await s.ticket({ svc: "legacy", pur: "agent_credential" }), "legacy");
    expect(res.status).toBe(200);
    const text = await res.text();
    expect(text).not.toContain("otpauth");
    expect(text).not.toContain(SEED);
    expect(JSON.parse(text).token.totpGenerated).toBe(true);
    const doc = (await s.ctx.storage.get("tokens", "legacy"))!;
    expect(JSON.stringify(doc)).not.toContain("otpauth");
    expect((doc.meta as Record<string, unknown>).totpPeriod).toBe(45);
    expect((await readTokenObject(s.key, doc)).totpSecret).toBe(SEED);
  });

  it("heals on /v1/storage list without leaking the URI", async () => {
    const s = setup();
    await seedLegacy(s);
    const res = await s.signed("/v1/storage", { operation: "list", collection: "tokens" });
    expect(res.status).toBe(200);
    const text = await res.text();
    expect(text).not.toContain("otpauth");
    expect(text).not.toContain(SEED);
    expect(JSON.stringify(await s.ctx.storage.get("tokens", "legacy"))).not.toContain("otpauth");
  });

  it("/v1/admin/migrate sweeps everything (counts only) and is idempotent", async () => {
    const s = setup();
    await seedLegacy(s, "a");
    await seedLegacy(s, "b");
    const res = await s.signed("/v1/admin/migrate", {});
    expect(await res.json()).toEqual({ status: "ok", totp: { scanned: 2, migrated: 2, failed: 0 } });
    const again = await s.signed("/v1/admin/migrate", {});
    expect(await again.json()).toEqual({ status: "ok", totp: { scanned: 2, migrated: 0, failed: 0 } });
  });

  it("unparseable legacy URI is never returned", async () => {
    const s = setup();
    const doc = await buildEncryptedTokenDocument(s.key, "x", null, {
      serviceName: "bad",
      totpUri: `otpauth://hotp/x?secret=${SEED}`,
    });
    await s.ctx.storage.set("tokens", "bad", doc);
    const res = await s.signed("/v1/storage", { operation: "get", collection: "tokens", key: "bad" });
    const text = await res.text();
    expect(text).not.toContain("otpauth");
    expect(text).not.toContain(SEED);
    const m = await s.signed("/v1/admin/migrate", {});
    expect(((await m.json()) as { totp: { failed: number } }).totp.failed).toBe(1);
  });
});

describe("ticketConstraints", () => {
  it("is advertised at /v1/health", async () => {
    const s = setup();
    const res = await s.app.request("https://wh.example/v1/health");
    const body = (await res.json()) as { capabilities: string[] };
    expect(body.capabilities).toContain("ticketConstraints");
  });

  it("mode=create refuses an existing service with 409 already_exists", async () => {
    const s = setup();
    expect((await s.store(await s.ticket({ mode: "create", cid: "c1" }), { accessToken: "a" })).status).toBe(200);
    const res = await s.store(await s.ticket({ mode: "create", cid: "c2" }), { accessToken: "b" });
    expect(res.status).toBe(409);
    expect(((await res.json()) as { error: string }).error).toBe("already_exists");
    expect(((await s.ctx.storage.get("tokens", "svc"))!.meta as Record<string, unknown>).creationId).toBe("c1");
  });

  it("mode=overwrite and absent mode overwrite, replacing creationId", async () => {
    const s = setup();
    await s.store(await s.ticket({ mode: "create", cid: "c1" }), { accessToken: "a" });
    expect((await s.store(await s.ticket({ mode: "overwrite", cid: "c2" }), { accessToken: "b" })).status).toBe(200);
    const meta = () => (async () => (await s.ctx.storage.get("tokens", "svc"))!.meta as Record<string, unknown>)();
    expect((await meta()).creationId).toBe("c2");
    expect((await s.store(await s.ticket({}), { accessToken: "c" })).status).toBe(200);
    expect((await meta()).creationId).toBeUndefined(); // absent cid = legacy behaviour: meta rebuilt, old creationId not carried
  });

  it("credential cid: match ok, mismatch 409 stale_creation, absent ok", async () => {
    const s = setup();
    await s.store(await s.ticket({ cid: "c1" }), { accessToken: "a" });
    const red = (cid?: string) =>
      s.ticket({ pur: "agent_credential", ...(cid ? { cid } : {}) }).then((t) => s.credential(t));
    expect((await red("c1")).status).toBe(200);
    expect((await red()).status).toBe(200);
    const stale = await red("other");
    expect(stale.status).toBe(409);
    expect(((await stale.json()) as { error: string }).error).toBe("stale_creation");
  });

  it("credential cid against a token with no creationId -> 409", async () => {
    const s = setup();
    await s.store(await s.ticket({}), { accessToken: "a" });
    const res = await s.credential(await s.ticket({ pur: "agent_credential", cid: "c1" }));
    expect(res.status).toBe(409);
  });

  it("proxy cid mismatch -> 409 stale_creation before any upstream call", async () => {
    const s = setup();
    await s.store(await s.ticket({ cid: "c1" }), { accessToken: "a" });
    const res = await s.signed("/v1/proxy", {
      ticket: await s.ticket({ pur: "proxy", cid: "zzz" }),
      service: "svc",
      upstream: { url: "https://upstream.invalid/x", method: "GET" },
      headerTemplates: {},
    });
    expect(res.status).toBe(409);
    expect(((await res.json()) as { error: string }).error).toBe("stale_creation");
  });
});
