// Security-review hardening: proxy redirects and Server-Timing, request body
// caps, tv-refresh refusing own-app tokens, audit-list option validation,
// provider-name lookups and the redirect-less token requests.

import { afterEach, describe, expect, it, vi } from "vitest";
import { createApp } from "../../src/core/app.ts";
import { allModules } from "../../src/modules/index.ts";
import { proxyModule } from "../../src/modules/proxy.ts";
import { storageModule } from "../../src/modules/storage.ts";
import { signTicket } from "../../src/core/protocol/tickets.ts";
import { computeRequestSignature } from "../../src/core/protocol/hmac.ts";
import { base64Encode, utf8 } from "../../src/core/crypto/encoding.ts";
import { buildEncryptedTokenDocument } from "../../src/core/protocol/tokendoc.ts";
import { PROVIDER_SLUG, providerEntry } from "../../src/core/protocol/oauthConnect.ts";
import { mintGcpAccessToken } from "../../src/modules/interceptors/gcpSa.ts";
import { configFromEnv } from "../../src/runtime/config.ts";
import type { TicketPayload } from "../../src/core/protocol/types.ts";
import { makeContext } from "../conformance/_harness.ts";

const secret = crypto.getRandomValues(new Uint8Array(32)) as Uint8Array<ArrayBuffer>;

afterEach(() => vi.unstubAllGlobals());

async function signedPost(app: ReturnType<typeof createApp>, path: string, payload: Record<string, unknown>) {
  const requestId = crypto.randomUUID();
  const body = JSON.stringify({ ...payload, attemptId: requestId });
  const ts = String(Math.floor(Date.now() / 1000));
  const sig = await computeRequestSignature(secret, ts, utf8(body));
  return app.request(path, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "X-TokenVault-Signature": `sha256=${sig}`,
      "X-TokenVault-Timestamp": ts,
      "X-TokenVault-Request-Id": requestId,
    },
    body,
  });
}

// ── WH-1 / WH-18: proxy redirects and Server-Timing ─────────────────────────

describe("proxy upstream redirects", () => {
  async function proxy(upstream: Record<string, unknown>) {
    const ctx = makeContext({ hmacSecret: secret });
    await ctx.storage.set("tokens", "github", { accessToken: "CRED" });
    const app = createApp(ctx, [proxyModule()]);
    const payload: TicketPayload = {
      sub: "u",
      svc: "github",
      pur: "proxy",
      iat: 1700000000,
      exp: 9999999999,
      nonce: crypto.randomUUID().replace(/-/g, ""),
    };
    return signedPost(app, "/v1/proxy", {
      ticket: await signTicket(secret, payload),
      service: "github",
      upstream: { url: "https://up.test/start", method: "GET", ...upstream },
      headerTemplates: { Authorization: "Bearer ${TOKEN}" },
    });
  }

  const redirect = (status: number, location: string) => new Response(null, { status, headers: { location } });
  const authOf = (call: unknown[]) => new Headers((call[1] as RequestInit).headers).get("authorization");

  it("never lets the runtime follow redirects, and follows a same-origin hop itself with the headers", async () => {
    const fetchMock = vi.fn(async (url: string | URL) =>
      String(url).endsWith("/start") ? redirect(302, "/next") : new Response("done"),
    );
    vi.stubGlobal("fetch", fetchMock);
    const res = await proxy({});
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("done");
    expect(fetchMock).toHaveBeenCalledTimes(2);
    for (const call of fetchMock.mock.calls) expect((call[1] as RequestInit).redirect).toBe("manual");
    expect(String(fetchMock.mock.calls[1]![0])).toBe("https://up.test/next");
    expect(authOf(fetchMock.mock.calls[1]!)).toBe("Bearer CRED");
  });

  it("does not follow a cross-origin redirect: the second host never sees the credential", async () => {
    const fetchMock = vi.fn(async () => redirect(302, "https://evil.test/steal"));
    vi.stubGlobal("fetch", fetchMock);
    const res = await proxy({});
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("https://evil.test/steal");
    expect(res.headers.get("x-upstream-status")).toBe("302");
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(JSON.stringify([...res.headers])).not.toContain("CRED");
    // A different port or scheme is a different origin too.
    for (const loc of ["https://up.test:8443/x", "http://up.test/x"]) {
      fetchMock.mockClear();
      fetchMock.mockImplementation(async () => redirect(307, loc));
      expect((await proxy({})).status).toBe(307);
      expect(fetchMock).toHaveBeenCalledTimes(1);
    }
  });

  it("stops after 5 same-origin hops and returns the redirect", async () => {
    const fetchMock = vi.fn(async () => redirect(302, "/again"));
    vi.stubGlobal("fetch", fetchMock);
    const res = await proxy({});
    expect(res.status).toBe(302);
    expect(fetchMock).toHaveBeenCalledTimes(6); // the request + 5 hops
  });

  it("re-sends method and body on 307/308 but drops them on 303 and on POST 301/302", async () => {
    const body = base64Encode(utf8("payload"));
    const run = async (status: number) => {
      const fetchMock = vi.fn(async (url: string | URL) =>
        String(url).endsWith("/start") ? redirect(status, "/next") : new Response("ok"),
      );
      vi.stubGlobal("fetch", fetchMock);
      await proxy({ method: "POST", body });
      return (fetchMock.mock.calls[1]![1] as RequestInit);
    };
    for (const status of [307, 308]) {
      const init = await run(status);
      expect(init.method).toBe("POST");
      expect(new TextDecoder().decode(init.body as Uint8Array)).toBe("payload");
    }
    for (const status of [301, 302, 303]) {
      const init = await run(status);
      expect(init.method).toBe("GET");
      expect(init.body).toBeUndefined();
    }
  });
});

describe("proxy Server-Timing", () => {
  it("drops tv-* entries the upstream sent and keeps the rest", async () => {
    const ctx = makeContext({ hmacSecret: secret });
    await ctx.storage.set("tokens", "github", { accessToken: "CRED" });
    const app = createApp(ctx, [proxyModule()]);
    vi.stubGlobal(
      "fetch",
      async () => new Response("x", { headers: { "Server-Timing": "db;dur=5, tv-up;dur=999, TV-wh;dur=999, cache;desc=hit" } }),
    );
    const res = await signedPost(app, "/v1/proxy", {
      ticket: await signTicket(secret, {
        sub: "u",
        svc: "github",
        pur: "proxy",
        iat: 1700000000,
        exp: 9999999999,
        nonce: crypto.randomUUID().replace(/-/g, ""),
      }),
      service: "github",
      upstream: { url: "https://up.test/x" },
      headerTemplates: {},
    });
    const timing = res.headers.get("server-timing")!;
    expect(timing).toContain("db;dur=5");
    expect(timing).toContain("cache;desc=hit");
    expect(timing).not.toContain("999");
    expect(timing.match(/tv-up/g)).toHaveLength(1);
    expect(timing.match(/tv-wh/gi)).toHaveLength(1);
  });
});

// ── WH-15: body caps ────────────────────────────────────────────────────────

describe("request body cap", () => {
  const small = () => {
    const ctx = makeContext({ hmacSecret: secret });
    ctx.config.maxBodyBytes = 64;
    ctx.config.maxProxyBodyBytes = 4096;
    return createApp(ctx, allModules());
  };

  it("refuses an oversized declared Content-Length with 413 in the error shape", async () => {
    const res = await small().request("/v1/storage", { method: "POST", body: "x".repeat(65) });
    expect(res.status).toBe(413);
    expect(((await res.json()) as { error: string }).error).toBe("payload_too_large");
  });

  it("counts streamed bytes when there is no Content-Length", async () => {
    const stream = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(utf8("x".repeat(40)));
        c.enqueue(utf8("x".repeat(40)));
        c.close();
      },
    });
    const res = await small().request("/v1/storage", {
      method: "POST",
      body: stream,
      duplex: "half",
    } as RequestInit);
    expect(res.status).toBe(413);
  });

  it("lets a small body through and gives /v1/proxy the larger limit", async () => {
    const app = small();
    expect((await app.request("/v1/storage", { method: "POST", body: "x".repeat(64) })).status).not.toBe(413);
    expect((await app.request("/v1/proxy", { method: "POST", body: "x".repeat(2000) })).status).not.toBe(413);
    expect((await app.request("/v1/proxy", { method: "POST", body: "x".repeat(5000) })).status).toBe(413);
  });

  it("reads the limits from env", () => {
    const cfg = configFromEnv((k) =>
      ({ TOKENVAULT_FRONTEND_URL: "https://tv.test", TV_MAX_BODY_BYTES: "2048", TV_MAX_PROXY_BODY_BYTES: "4096" })[k as string],
    );
    expect(cfg.maxBodyBytes).toBe(2048);
    expect(cfg.maxProxyBodyBytes).toBe(4096);
  });
});

// ── WH-7: tv-refresh refuses own-app tokens ─────────────────────────────────

describe("tv-refresh get", () => {
  it("refuses a token minted by /v1/oauth/callback, and still serves a pasted one", async () => {
    const ctx = makeContext({ hmacSecret: secret });
    const key = await ctx.secrets.encryptionKey();
    await ctx.storage.set(
      "tokens",
      "own",
      await buildEncryptedTokenDocument(key, "AT", "RT-own", { oauth: { provider: "google" } }),
    );
    await ctx.storage.set("tokens", "pasted", await buildEncryptedTokenDocument(key, "AT", "RT-pasted", {}));
    const app = createApp(ctx, allModules({ tvRefreshEnabled: true }));

    const own = await (await signedPost(app, "/v1/refresh", { action: "get", service: "own" })).text();
    expect(JSON.parse(own).status).toBe("webhook_managed");
    expect(own).not.toContain("RT-own");

    const pasted = (await (await signedPost(app, "/v1/refresh", { action: "get", service: "pasted" })).json()) as {
      status: string;
      refreshToken: string;
    };
    expect(pasted.status).toBe("ok");
    expect(pasted.refreshToken).toBe("RT-pasted");
  });
});

// ── WH-11: audit list options ───────────────────────────────────────────────

describe("storage list options", () => {
  it("answers 400 invalid_request for a non-string after or since", async () => {
    const ctx = makeContext({ hmacSecret: secret });
    const app = createApp(ctx, [storageModule()]);
    for (const options of [{ limit: 5, after: 123 }, { limit: 5, since: { a: 1 } }, { after: ["x"] }]) {
      const res = await signedPost(app, "/v1/storage", { operation: "list", collection: "audit", options });
      expect(res.status).toBe(400);
      expect(((await res.json()) as { error: string }).error).toBe("invalid_request");
    }
    const ok = await signedPost(app, "/v1/storage", { operation: "list", collection: "audit", options: { limit: 5 } });
    expect(ok.status).toBe(200);
  });
});

// ── WH-12: provider lookups ─────────────────────────────────────────────────

describe("provider names", () => {
  it("resolves only own entries under a valid slug", () => {
    const map = { google: { clientSecret: "s" } };
    expect(providerEntry(map, "google")).toBeDefined();
    for (const name of ["constructor", "__proto__", "toString", "hasOwnProperty", "Google", ""]) {
      expect(providerEntry(map, name)).toBeUndefined();
    }
    expect(PROVIDER_SLUG.test("my-app_1")).toBe(true);
    expect(PROVIDER_SLUG.test("-x")).toBe(false);
  });

  it("builds OAUTH_PROVIDERS_JSON into a prototype-less map and drops invalid names", () => {
    const json = '{"Google":{"clientSecret":"s"},"__proto__":{"clientSecret":"p"},"bad name":{"clientSecret":"q"}}';
    const cfg = configFromEnv((k) => ({ TOKENVAULT_FRONTEND_URL: "https://tv.test", OAUTH_PROVIDERS_JSON: json })[k as string]);
    const map = cfg.oauthProviders!;
    expect(Object.getPrototypeOf(map)).toBeNull();
    expect(Object.keys(map)).toEqual(["google"]);
    expect((map as Record<string, unknown>).constructor).toBeUndefined();
  });
});

// ── WH-8: token requests never follow redirects ─────────────────────────────

describe("gcp token request", () => {
  it("sets redirect: error and maps a failure to gcp_mint_failed", async () => {
    const pair = await crypto.subtle.generateKey(
      { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      true,
      ["sign", "verify"],
    );
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
    const key = JSON.stringify({
      type: "service_account",
      client_email: "redir@example.test",
      private_key: `-----BEGIN PRIVATE KEY-----\n${base64Encode(pkcs8)}\n-----END PRIVATE KEY-----\n`,
    });
    const fetchMock = vi.fn(async (_url: string | URL, init?: RequestInit) => {
      if (init?.redirect === "error") throw new TypeError("redirect mode is set to error");
      return Response.json({ access_token: "x", expires_in: 3600 });
    });
    vi.stubGlobal("fetch", fetchMock);
    await expect(mintGcpAccessToken(key, "gcp-redir")).rejects.toMatchObject({ code: "gcp_mint_failed" });
    expect((fetchMock.mock.calls[0]![1] as RequestInit).redirect).toBe("error");
  });
});
