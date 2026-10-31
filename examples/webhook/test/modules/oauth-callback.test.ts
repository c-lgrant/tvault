// /v1/oauth/callback (capability `oauth-callback`): state ticket verification,
// PKCE derivation parity, code exchange with the LOCAL client secret, and the
// no-secrets-in-the-redirect guarantee.

import { afterEach, describe, expect, it, vi } from "vitest";
import { createApp } from "../../src/core/app.ts";
import { allModules } from "../../src/modules/index.ts";
import { signTicket } from "../../src/core/protocol/tickets.ts";
import { derivePkceVerifier, pkceChallenge, sha256Hex } from "../../src/core/protocol/oauthConnect.ts";
import { readTokenObject } from "../../src/core/protocol/tokendoc.ts";
import type { TicketPayload } from "../../src/core/protocol/types.ts";
import { makeContext } from "../conformance/_harness.ts";

// Parity vector shared with the control plane's tests: same secret bytes, same
// nonce, same outputs on both sides.
const VECTOR_SECRET = Uint8Array.from({ length: 32 }, (_, i) => i) as Uint8Array<ArrayBuffer>;
const VECTOR_NONCE = "0123456789abcdef0123456789abcdef";
const VECTOR_VERIFIER = "VdqfFLJJny0ymbH0l91qjwz2kRjq_wIjWf_gn5SmEgw";
const VECTOR_CHALLENGE = "fO8Zordyurr3pXrF1yZqffrkMGRKyGVxXohEw4Ekxwg";

const EXTERNAL = "https://wh.example";
const CALLBACK = `${EXTERNAL}/v1/oauth/callback`;
const TOKEN_URL = "https://oauth2.googleapis.com/token";

afterEach(() => vi.unstubAllGlobals());

function setup(opts: { providers?: boolean } = {}) {
  const hmac = crypto.getRandomValues(new Uint8Array(32)) as Uint8Array<ArrayBuffer>;
  const key = crypto.getRandomValues(new Uint8Array(32)) as Uint8Array<ArrayBuffer>;
  const ctx = makeContext({ hmacSecret: hmac, encryptionKey: key });
  ctx.config.externalUrl = EXTERNAL;
  if (opts.providers !== false) ctx.config.oauthProviders = { google: { clientSecret: "local-secret" } };
  const app = createApp(ctx, allModules());
  const state = (o: Partial<TicketPayload> = {}) =>
    signTicket(hmac, {
      sub: "u",
      svc: "my-gmail",
      pur: "oauth_connect",
      prv: "google",
      tku: TOKEN_URL,
      clid: "client-123.apps.example",
      rdu: CALLBACK,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 600,
      nonce: crypto.randomUUID().replace(/-/g, ""),
      ...o,
    });
  // The browser that started the flow holds sha256(nonce) in a cookie; pass
  // `cookie: false` for a browser that did not, or a string to forge one.
  const callback = async (params: Record<string, string>, cookie: boolean | string = true) => {
    const headers: Record<string, string> = {};
    if (cookie !== false && params.state) {
      const nonce = JSON.parse(atob(params.state!.split(".")[0]!.replace(/-/g, "+").replace(/_/g, "/"))).nonce as string;
      headers.cookie = `tv_oauth_state=${typeof cookie === "string" ? cookie : await sha256Hex(nonce)}`;
    }
    return app.request(`${EXTERNAL}/v1/oauth/callback?${new URLSearchParams(params)}`, { headers });
  };
  const start = (st: string) => app.request(`${EXTERNAL}/v1/oauth/start?${new URLSearchParams({ state: st })}`);
  return { hmac, key, ctx, app, state, callback, start };
}

function stubProvider(body: unknown = { access_token: "AT-secret", refresh_token: "RT-secret", expires_in: 3600, scope: "a b" }, status = 200) {
  const fetchMock = vi.fn(async (_url: string, _init?: RequestInit) => new Response(JSON.stringify(body), { status }));
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function resultOf(res: Response) {
  expect(res.status).toBe(302);
  return new URL(res.headers.get("location")!);
}

describe("PKCE derivation", () => {
  it("matches the shared parity vector", async () => {
    const verifier = await derivePkceVerifier(VECTOR_SECRET, VECTOR_NONCE);
    expect(verifier).toBe(VECTOR_VERIFIER);
    expect(verifier).toHaveLength(43);
    expect(await pkceChallenge(verifier)).toBe(VECTOR_CHALLENGE);
  });
});

describe("capability", () => {
  it("is advertised at /v1/health", async () => {
    const s = setup();
    const body = (await (await s.app.request(`${EXTERNAL}/v1/health`)).json()) as { capabilities: string[] };
    expect(body.capabilities).toContain("oauth-callback");
  });
});

describe("GET /v1/oauth/callback", () => {
  it("exchanges the code with the local secret + derived verifier and stores the token", async () => {
    const s = setup();
    const fetchMock = stubProvider();
    const nonce = "a".repeat(32);
    const res = await s.callback({ code: "the-code", state: await s.state({ nonce }) });

    const loc = resultOf(res);
    expect(loc.origin).toBe("https://tokenvault.test");
    expect(loc.pathname).toBe("/tokens/oauth-result");
    expect(loc.searchParams.get("status")).toBe("ok");
    expect(loc.searchParams.get("service")).toBe("my-gmail");
    // Nothing secret in the redirect.
    expect(loc.toString()).not.toContain("the-code");
    expect(loc.toString()).not.toContain("secret");

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe(TOKEN_URL);
    const sent = new URLSearchParams(String(init!.body));
    expect(sent.get("grant_type")).toBe("authorization_code");
    expect(sent.get("code")).toBe("the-code");
    expect(sent.get("client_secret")).toBe("local-secret");
    expect(sent.get("client_id")).toBe("client-123.apps.example");
    expect(sent.get("redirect_uri")).toBe(CALLBACK);
    expect(sent.get("code_verifier")).toBe(await derivePkceVerifier(s.hmac, nonce));

    const doc = await s.ctx.storage.get("tokens", "my-gmail");
    const tok = await readTokenObject(s.key, doc!);
    expect(tok.accessToken).toBe("AT-secret");
    expect(tok.refreshToken).toBe("RT-secret");
    expect(tok.hasRefreshToken).toBe(true);
    expect(tok.provider).toBe("google");
    expect(tok.oauth).toEqual({ provider: "google", tokenUrl: TOKEN_URL, clientId: "client-123.apps.example" });
    expect(typeof tok.expiryTime).toBe("number");
    // Stored encrypted, not as plaintext meta.
    expect(JSON.stringify(doc!.meta)).not.toContain("AT-secret");
  });

  it("is one-shot: a replayed state is refused and exchanges nothing", async () => {
    const s = setup();
    const fetchMock = stubProvider();
    const state = await s.state();
    expect(resultOf(await s.callback({ code: "c", state })).searchParams.get("status")).toBe("ok");
    const again = resultOf(await s.callback({ code: "c", state }));
    expect(again.searchParams.get("code")).toBe("state_invalid");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("refuses a bad signature, a missing state and the wrong purpose", async () => {
    const s = setup();
    const fetchMock = stubProvider();
    const good = await s.state();
    const tampered = `${good.split(".")[0]}.${"0".repeat(64)}`;
    expect(resultOf(await s.callback({ code: "c", state: tampered })).searchParams.get("code")).toBe("state_invalid");
    expect(resultOf(await s.callback({ code: "c" })).searchParams.get("code")).toBe("state_invalid");
    const store = await s.state({ pur: "store" });
    expect(resultOf(await s.callback({ code: "c", state: store })).searchParams.get("code")).toBe("state_invalid");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("refuses an expired state", async () => {
    const s = setup();
    stubProvider();
    const state = await s.state({ exp: Math.floor(Date.now() / 1000) - 5 });
    expect(resultOf(await s.callback({ code: "c", state })).searchParams.get("code")).toBe("state_expired");
  });

  it("refuses a state naming a different redirect URI", async () => {
    const s = setup();
    const fetchMock = stubProvider();
    const state = await s.state({ rdu: "https://evil.example/v1/oauth/callback" });
    expect(resultOf(await s.callback({ code: "c", state })).searchParams.get("code")).toBe("redirect_mismatch");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("never sends the client secret to a token URL it was not configured with", async () => {
    const s = setup();
    const fetchMock = stubProvider();
    const state = await s.state({ tku: "https://evil.example/token" });
    expect(resultOf(await s.callback({ code: "c", state })).searchParams.get("code")).toBe("token_url_mismatch");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("uses an operator-configured token URL for providers outside the built-in table", async () => {
    const s = setup({ providers: false });
    s.ctx.config.oauthProviders = {
      acme: { clientSecret: "s", clientId: "acme-id", tokenUrl: "https://auth.acme.example/token" },
    };
    const fetchMock = stubProvider();
    const state = await s.state({ prv: "acme", tku: "https://auth.acme.example/token", clid: "acme-id" });
    expect(resultOf(await s.callback({ code: "c", state })).searchParams.get("status")).toBe("ok");
    expect(String(fetchMock.mock.calls[0]![0])).toBe("https://auth.acme.example/token");
  });

  it("refuses when no client secret is configured locally", async () => {
    const s = setup({ providers: false });
    const fetchMock = stubProvider();
    const loc = resultOf(await s.callback({ code: "c", state: await s.state() }));
    expect(loc.searchParams.get("code")).toBe("provider_not_configured");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("refuses a client id that differs from the locally configured one", async () => {
    const s = setup();
    s.ctx.config.oauthProviders = { google: { clientSecret: "x", clientId: "other-id" } };
    const fetchMock = stubProvider();
    const loc = resultOf(await s.callback({ code: "c", state: await s.state() }));
    expect(loc.searchParams.get("code")).toBe("client_mismatch");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("reports a user denial and a failed exchange as short codes, stores nothing", async () => {
    const s = setup();
    stubProvider({ error: "invalid_grant", error_description: "Bad code AT-leak" }, 400);
    const denied = resultOf(await s.callback({ error: "access_denied", state: await s.state() }));
    expect(denied.searchParams.get("code")).toBe("access_denied");
    const failed = resultOf(await s.callback({ code: "c", state: await s.state() }));
    expect(failed.searchParams.get("code")).toBe("exchange_failed");
    expect(failed.toString()).not.toContain("AT-leak");
    expect(await s.ctx.storage.get("tokens", "my-gmail")).toBeNull();
  });

  it("keeps createdAt when reconnecting an existing service", async () => {
    const s = setup();
    stubProvider();
    await s.callback({ code: "c", state: await s.state() });
    const first = (await s.ctx.storage.get("tokens", "my-gmail"))!.meta as Record<string, unknown>;
    await new Promise((r) => setTimeout(r, 1100));
    await s.callback({ code: "c", state: await s.state() });
    const second = (await s.ctx.storage.get("tokens", "my-gmail"))!.meta as Record<string, unknown>;
    expect(second.createdAt).toBe(first.createdAt);
    expect(second.updatedAt).not.toBe(first.updatedAt);
  });
});

describe("GET /v1/oauth/start (browser binding)", () => {
  it("sets an HttpOnly cookie bound to the nonce and redirects to the provider authorize URL", async () => {
    const s = setup();
    const nonce = "b".repeat(32);
    const res = await s.start(await s.state({ nonce, scp: "openid email" }));
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("location")!);
    expect(`${loc.origin}${loc.pathname}`).toBe("https://accounts.google.com/o/oauth2/v2/auth");
    expect(loc.searchParams.get("client_id")).toBe("client-123.apps.example");
    expect(loc.searchParams.get("redirect_uri")).toBe(CALLBACK);
    expect(loc.searchParams.get("scope")).toBe("openid email");
    expect(loc.searchParams.get("code_challenge")).toBe(await pkceChallenge(await derivePkceVerifier(s.hmac, nonce)));
    expect(loc.searchParams.get("code_challenge_method")).toBe("S256");
    expect(loc.searchParams.get("access_type")).toBe("offline");
    const cookie = res.headers.get("set-cookie")!;
    expect(cookie).toContain(`tv_oauth_state=${await sha256Hex(nonce)}`);
    for (const attr of ["HttpOnly", "Secure", "SameSite=Lax", "Max-Age=600"]) expect(cookie).toContain(attr);
  });

  it("does not consume the state, so the real callback still works after it", async () => {
    const s = setup();
    stubProvider();
    const st = await s.state();
    expect((await s.start(st)).status).toBe(302);
    expect((await s.start(st)).status).toBe(302);
    expect(resultOf(await s.callback({ code: "c", state: st })).searchParams.get("status")).toBe("ok");
  });

  it("refuses a bad state, a foreign redirect URI and an unconfigured provider without redirecting to the provider", async () => {
    const s = setup();
    const bad = resultOf(await s.start(`${(await s.state()).split(".")[0]}.${"0".repeat(64)}`));
    expect(bad.pathname).toBe("/tokens/oauth-result");
    expect(bad.searchParams.get("code")).toBe("state_invalid");
    const foreign = resultOf(await s.start(await s.state({ rdu: "https://evil.example/v1/oauth/callback" })));
    expect(foreign.searchParams.get("code")).toBe("redirect_mismatch");
    const none = setup({ providers: false });
    expect(resultOf(await none.start(await none.state())).searchParams.get("code")).toBe("provider_not_configured");
  });
});

describe("callback browser binding (OAuth login CSRF)", () => {
  it("refuses a browser without the cookie or with the wrong one, and keeps the state usable", async () => {
    const s = setup();
    const fetchMock = stubProvider();
    const st = await s.state();
    expect(resultOf(await s.callback({ code: "c", state: st }, false)).searchParams.get("code")).toBe("browser_mismatch");
    expect(resultOf(await s.callback({ code: "c", state: st }, "f".repeat(64))).searchParams.get("code")).toBe("browser_mismatch");
    expect(fetchMock).not.toHaveBeenCalled();
    expect(await s.ctx.storage.get("tokens", "my-gmail")).toBeNull();
    // The legitimate browser can still finish.
    expect(resultOf(await s.callback({ code: "c", state: st })).searchParams.get("status")).toBe("ok");
  });

  it("clears the cookie on the way out", async () => {
    const s = setup();
    stubProvider();
    const res = await s.callback({ code: "c", state: await s.state() });
    expect(res.headers.get("set-cookie")).toMatch(/tv_oauth_state=;.*Max-Age=0/);
  });
});

describe("refresh-notify reads the stored oauth hint", () => {
  it("refreshes a callback-minted token under a custom service name without a TV hint", async () => {
    const s = setup();
    stubProvider();
    await s.callback({ code: "c", state: await s.state() });
    // refresh call
    const { computeRequestSignature } = await import("../../src/core/protocol/hmac.ts");
    const { utf8 } = await import("../../src/core/crypto/encoding.ts");
    const fetchMock = stubProvider({ access_token: "AT2", expires_in: 100 });
    const body = JSON.stringify({ service: "my-gmail" });
    const ts = String(Math.floor(Date.now() / 1000));
    const sig = await computeRequestSignature(s.hmac, ts, utf8(body));
    const res = await s.app.request(`${EXTERNAL}/v1/refresh-notify`, {
      method: "POST",
      body,
      headers: {
        "content-type": "application/json",
        "X-TokenVault-Signature": `sha256=${sig}`,
        "X-TokenVault-Timestamp": ts,
        "X-TokenVault-Request-Id": crypto.randomUUID(),
      },
    });
    expect(((await res.json()) as { status: string }).status).toBe("refreshed");
    const sent = new URLSearchParams(String(fetchMock.mock.calls[0]![1]!.body));
    expect(sent.get("grant_type")).toBe("refresh_token");
    expect(sent.get("client_id")).toBe("client-123.apps.example");
    const tok = await readTokenObject(s.key, (await s.ctx.storage.get("tokens", "my-gmail"))!);
    expect(tok.accessToken).toBe("AT2");
    expect(tok.refreshToken).toBe("RT-secret");
    expect((tok.oauth as { provider: string }).provider).toBe("google");
  });
});

describe("refresh-notify never sends the client secret to a URL TV chose", () => {
  async function refresh(s: ReturnType<typeof setup>, body: Record<string, unknown>) {
    const { computeRequestSignature } = await import("../../src/core/protocol/hmac.ts");
    const { utf8 } = await import("../../src/core/crypto/encoding.ts");
    const raw = JSON.stringify(body);
    const ts = String(Math.floor(Date.now() / 1000));
    const sig = await computeRequestSignature(s.hmac, ts, utf8(raw));
    const res = await s.app.request(`${EXTERNAL}/v1/refresh-notify`, {
      method: "POST",
      body: raw,
      headers: {
        "content-type": "application/json",
        "X-TokenVault-Signature": `sha256=${sig}`,
        "X-TokenVault-Timestamp": ts,
        "X-TokenVault-Request-Id": crypto.randomUUID(),
      },
    });
    return (await res.json()) as { status: string };
  }

  async function connected() {
    const s = setup();
    stubProvider();
    await s.callback({ code: "c", state: await s.state() });
    return s;
  }

  it("refuses a hint whose tokenUrl differs from the built-in one", async () => {
    const s = await connected();
    const fetchMock = stubProvider({ access_token: "x" });
    const out = await refresh(s, {
      service: "my-gmail",
      refreshHint: { provider: "google", tokenUrl: "https://evil.example/token" },
    });
    expect(out.status).toBe("refresh_failed");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("refuses a stored hint whose tokenUrl was tampered with", async () => {
    const s = await connected();
    const doc = (await s.ctx.storage.get("tokens", "my-gmail"))!;
    (doc.meta as Record<string, any>).oauth.tokenUrl = "https://evil.example/token";
    await s.ctx.storage.set("tokens", "my-gmail", doc);
    const fetchMock = stubProvider({ access_token: "x" });
    expect((await refresh(s, { service: "my-gmail" })).status).toBe("refresh_failed");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("does not follow a hint for a provider with no local or built-in token URL", async () => {
    const s = await connected();
    s.ctx.config.oauthProviders = { acme: { clientSecret: "s", clientId: "acme-id" } };
    const doc = (await s.ctx.storage.get("tokens", "my-gmail"))!;
    (doc.meta as Record<string, any>).oauth = { provider: "acme", tokenUrl: "https://evil.example/token", clientId: "acme-id" };
    await s.ctx.storage.set("tokens", "my-gmail", doc);
    const fetchMock = stubProvider({ access_token: "x" });
    const out = await refresh(s, { service: "my-gmail" });
    expect(out.status).toBe("acknowledged");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("uses the operator's tokenUrl, and a matching hint is fine", async () => {
    const s = await connected();
    s.ctx.config.oauthProviders = { google: { clientSecret: "s", tokenUrl: "https://auth.mine.example/token" } };
    const doc = (await s.ctx.storage.get("tokens", "my-gmail"))!;
    (doc.meta as Record<string, any>).oauth.tokenUrl = "https://auth.mine.example/token";
    await s.ctx.storage.set("tokens", "my-gmail", doc);
    const fetchMock = stubProvider({ access_token: "x" });
    const out = await refresh(s, {
      service: "my-gmail",
      refreshHint: { provider: "google", tokenUrl: "https://auth.mine.example/token" },
    });
    expect(out.status).toBe("refreshed");
    expect(String(fetchMock.mock.calls[0]![0])).toBe("https://auth.mine.example/token");
  });
});
