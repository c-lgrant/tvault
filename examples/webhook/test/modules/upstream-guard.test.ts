// The webhook's own limits on what the control plane can make it do:
// /v1/storage never returns a credential document, and /v1/proxy refuses
// private upstreams and origins outside the operator's allowlist.

import { afterEach, describe, expect, it, vi } from "vitest";
import { createApp } from "../../src/core/app.ts";
import { proxyModule } from "../../src/modules/proxy.ts";
import { storageModule } from "../../src/modules/storage.ts";
import { signTicket } from "../../src/core/protocol/tickets.ts";
import { computeRequestSignature } from "../../src/core/protocol/hmac.ts";
import { utf8 } from "../../src/core/crypto/encoding.ts";
import { buildEncryptedTokenDocument } from "../../src/core/protocol/tokendoc.ts";
import { isPrivateAddress, isPrivateHost, parseProxyAllowedOrigins } from "../../src/core/protocol/upstreamGuard.ts";
import { configFromEnv } from "../../src/runtime/config.ts";
import type { RuntimeContext } from "../../src/runtime/context.ts";
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

describe("/v1/storage get on tokens", () => {
  async function get(collection: string, key: string, seed: (ctx: RuntimeContext) => Promise<void>) {
    const ctx = makeContext({ hmacSecret: secret });
    await seed(ctx);
    const res = await signedPost(createApp(ctx, [storageModule()]), "/v1/storage", { operation: "get", collection, key });
    expect(res.status).toBe(200);
    return { text: await res.clone().text(), data: ((await res.json()) as { data: Record<string, unknown> | null }).data };
  }

  it("returns metadata only for an encrypted document", async () => {
    const { text, data } = await get("tokens", "github", async (ctx) => {
      const key = await ctx.secrets.encryptionKey();
      const doc = await buildEncryptedTokenDocument(key, "AT-secret", "RT-secret", { serviceName: "github", tokenType: "oauth" });
      await ctx.storage.set("tokens", "github", doc);
    });
    expect(data).toMatchObject({ serviceName: "github", tokenType: "oauth" });
    for (const k of ["fields", "v", "alg", "accessToken", "refreshToken"]) expect(data).not.toHaveProperty(k);
    expect(text).not.toContain("AT-secret");
  });

  it("returns metadata only for an old plaintext document", async () => {
    const { text, data } = await get("tokens", "legacy", async (ctx) => {
      await ctx.storage.set("tokens", "legacy", { accessToken: "PLAIN-secret", refreshToken: "RT", tokenType: "pat" });
    });
    expect(data).toEqual({ serviceName: "legacy", tokenType: "pat", hasRefreshToken: true });
    expect(text).not.toContain("PLAIN-secret");
  });

  it("answers null for a missing credential and leaves other collections as they were", async () => {
    expect((await get("tokens", "nope", async () => {})).data).toBeNull();
    const settings = { mode: "webhook" };
    const { data } = await get("vault_config", "settings", async (ctx) => {
      await ctx.storage.set("vault_config", "settings", settings);
    });
    expect(data).toEqual(settings);
  });
});

describe("private host detection", () => {
  it.each([
    "localhost",
    "db",
    "printer.local",
    "svc.internal",
    "nas.lan",
    "127.0.0.1",
    "10.1.2.3",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.1.1",
    "169.254.169.254",
    "100.64.0.1",
    "0.0.0.0",
    "[::1]",
    "[::]",
    "[fd00::1]",
    "[fe80::1]",
    "[::ffff:7f00:1]",
    "[::ffff:10.0.0.1]",
    "[64:ff9b::a00:1]",
    "[64:ff9b:1::a00:1]",
    "[2001::1]",
    "[2001:db8::1]",
    "[100::1]",
    "[::7f00:1]",
    "[2002:7f00:1::1]",
    "[ff02::1]",
  ])("%s is private", (host) => {
    expect(isPrivateHost(host)).toBe(true);
  });

  it.each(["example.com", "api.github.com", "8.8.8.8", "172.32.0.1", "100.128.0.1", "[2606:4700::1111]", "[::ffff:808:808]"])(
    "%s is public",
    (host) => {
      expect(isPrivateHost(host)).toBe(false);
    },
  );

  it("reads the forms a URL normalises", () => {
    for (const raw of ["http://2130706433/", "http://0x7f.1/", "http://017700000001/", "http://127.1/"]) {
      expect(isPrivateHost(new URL(raw).hostname)).toBe(true);
    }
    expect(isPrivateAddress("fe80::1%eth0")).toBe(true);
    expect(isPrivateAddress("not-an-address")).toBe(false);
  });
});

describe("TV_PROXY_ALLOWED_ORIGINS", () => {
  it("normalises entries to origins", () => {
    expect(parseProxyAllowedOrigins('{"github":["https://api.github.com/v3/"],"*":["https://mcp.example.com:8443"]}')).toEqual({
      github: ["https://api.github.com"],
      "*": ["https://mcp.example.com:8443"],
    });
    expect(parseProxyAllowedOrigins(undefined)).toBeUndefined();
    expect(parseProxyAllowedOrigins("  ")).toBeUndefined();
  });

  it("stops the webhook when the list cannot be read", () => {
    const env = (v: string) => (k: string) =>
      ({ TOKENVAULT_FRONTEND_URL: "https://tokenvault.test", TV_PROXY_ALLOWED_ORIGINS: v })[k];
    for (const bad of ["not json", "[]", '{"github":"https://x.example"}', '{"github":["ftp://x.example"]}', '{"github":[7]}']) {
      expect(() => configFromEnv(env(bad))).toThrow(/TV_PROXY_ALLOWED_ORIGINS/);
    }
    expect(configFromEnv(env('{"github":["https://api.github.com"]}')).proxyAllowedOrigins).toEqual({
      github: ["https://api.github.com"],
    });
  });
});

describe("/v1/proxy upstream rules", () => {
  async function proxy(url: string, tune: (ctx: RuntimeContext) => void = () => {}) {
    const ctx = makeContext({ hmacSecret: secret });
    tune(ctx);
    await ctx.storage.set("tokens", "github", { accessToken: "CRED" });
    const fetchMock = vi.fn(async (_url: unknown, _init?: RequestInit) => new Response("ok"));
    vi.stubGlobal("fetch", fetchMock);
    const payload: TicketPayload = {
      sub: "u",
      svc: "github",
      pur: "proxy",
      iat: 1700000000,
      exp: 9999999999,
      nonce: crypto.randomUUID().replace(/-/g, ""),
    };
    const res = await signedPost(createApp(ctx, [proxyModule()]), "/v1/proxy", {
      ticket: await signTicket(secret, payload),
      service: "github",
      upstream: { url, method: "GET" },
      headerTemplates: { Authorization: "Bearer ${TOKEN}" },
    });
    return { res, fetchMock, text: await res.clone().text() };
  }

  it("refuses a private upstream before the credential is used", async () => {
    for (const url of ["http://127.0.0.1:8080/x", "https://169.254.169.254/latest", "https://db.internal/x", "http://[::1]/x"]) {
      const { res, fetchMock, text } = await proxy(url);
      expect(res.status).toBe(403);
      expect(((await res.json()) as { error: string }).error).toBe("upstream_not_allowed");
      expect(fetchMock).not.toHaveBeenCalled();
      expect(text).not.toContain("CRED");
    }
  });

  it("refuses a name that resolves to a private address where the runtime can resolve", async () => {
    const tune = (addresses: string[]) => (ctx: RuntimeContext) => {
      ctx.resolveHost = async () => addresses;
    };
    const blocked = await proxy("https://rebind.example/x", tune(["93.184.216.34", "10.0.0.5"]));
    expect(blocked.res.status).toBe(403);
    expect(blocked.fetchMock).not.toHaveBeenCalled();
    const open = await proxy("https://ok.example/x", tune(["93.184.216.34"]));
    expect(open.res.status).toBe(200);
  });

  it("does not call a name it could not resolve", async () => {
    const { res, fetchMock } = await proxy("https://gone.example/x", (ctx) => {
      ctx.resolveHost = async () => {
        throw new Error("ENOTFOUND");
      };
    });
    expect(res.status).toBe(502);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("never lets a header name another host", async () => {
    const ctx = makeContext({ hmacSecret: secret });
    ctx.config.proxyAllowedOrigins = { github: ["https://api.github.com"] };
    await ctx.storage.set("tokens", "github", { accessToken: "CRED" });
    const fetchMock = vi.fn(async (_url: unknown, _init?: RequestInit) => new Response("ok"));
    vi.stubGlobal("fetch", fetchMock);
    const send = async (extra: Record<string, unknown>) =>
      signedPost(createApp(ctx, [proxyModule()]), "/v1/proxy", {
        ticket: await signTicket(secret, {
          sub: "u",
          svc: "github",
          pur: "proxy",
          iat: 1700000000,
          exp: 9999999999,
          nonce: crypto.randomUUID().replace(/-/g, ""),
        }),
        service: "github",
        upstream: { url: "https://api.github.com/user", method: "GET" },
        headerTemplates: { Authorization: "Bearer ${TOKEN}" },
        ...extra,
      });

    // Forwarded request headers: dropped.
    const forwarded = await send({
      upstream: {
        url: "https://api.github.com/user",
        method: "GET",
        headers: { Host: "evil.example", "X-Forwarded-Host": "evil.example", Forwarded: "host=evil.example", Accept: "a/b" },
      },
    });
    expect(forwarded.status).toBe(200);
    const sent = new Headers((fetchMock.mock.calls[0]![1] as RequestInit).headers);
    expect(sent.get("host")).toBeNull();
    expect(sent.get("x-forwarded-host")).toBeNull();
    expect(sent.get("forwarded")).toBeNull();
    expect(sent.get("accept")).toBe("a/b");

    // A template that sets one: refused, no call.
    const templated = await send({ headerTemplates: { Authorization: "Bearer ${TOKEN}", HOST: "evil.example" } });
    expect(templated.status).toBe(400);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("calls a private upstream when the operator allowed it", async () => {
    const { res, fetchMock } = await proxy("http://127.0.0.1:8080/x", (ctx) => {
      ctx.config.proxyAllowPrivate = true;
    });
    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("refuses anything that is not http or https", async () => {
    for (const url of ["file:///etc/passwd", "ftp://up.example/x", "not a url"]) {
      const { res, fetchMock } = await proxy(url);
      expect(res.status).toBe(400);
      expect(fetchMock).not.toHaveBeenCalled();
    }
  });

  it("with an allowlist, sends the credential only to a listed origin", async () => {
    const allow = (list: Record<string, string[]>) => (ctx: RuntimeContext) => {
      ctx.config.proxyAllowedOrigins = list;
    };
    const listed = await proxy("https://api.github.com/user", allow({ github: ["https://api.github.com"] }));
    expect(listed.res.status).toBe(200);

    const other = await proxy("https://evil.example/collect", allow({ github: ["https://api.github.com"] }));
    expect(other.res.status).toBe(403);
    expect(((await other.res.json()) as { error: string }).error).toBe("upstream_not_allowed");
    expect(other.fetchMock).not.toHaveBeenCalled();

    // A different port or scheme is a different origin.
    expect((await proxy("https://api.github.com:8443/user", allow({ github: ["https://api.github.com"] }))).res.status).toBe(403);
    // A service with no entry is closed once a list exists; "*" covers every service.
    expect((await proxy("https://api.github.com/user", allow({ slack: ["https://api.github.com"] }))).res.status).toBe(403);
    expect((await proxy("https://mcp.example.com/mcp", allow({ "*": ["https://mcp.example.com"] }))).res.status).toBe(200);
  });

  it("without an allowlist, any public origin is called as before", async () => {
    const { res, fetchMock } = await proxy("https://anything.example/x");
    expect(res.status).toBe(200);
    expect(new Headers((fetchMock.mock.calls[0]![1] as RequestInit).headers).get("authorization")).toBe("Bearer CRED");
  });
});
