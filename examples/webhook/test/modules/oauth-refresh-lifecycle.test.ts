// End-to-end lifecycle of a credential connected with the user's OWN OAuth app
// (capability `oauth-callback`), against fake provider token endpoints:
//
//   connect (/v1/oauth/start + /v1/oauth/callback, code exchange)
//   -> scheduled refresh of a near-expiry token (refreshDueTokens)
//   -> refresh-token rotation persisted
//   -> manual refresh (/v1/refresh-notify, TV's Refresh button)
//   -> failures: invalid_grant (reconnect), provider down (transient), GitHub's
//      HTTP-200 error bodies
//   -> agent fetch after expiry (/v1/credential refreshes on demand)
//
// plus the quirks of the three built-in providers:
//   google  — needs access_type=offline + prompt=consent for a refresh token;
//             refresh responses omit refresh_token (no rotation).
//   github  — OAuth Apps: no expiry, no refresh token. GitHub Apps with
//             expiring user tokens: 8 h access, refresh token rotates on every
//             refresh. Errors come back as HTTP 200 + {"error": …}.
//   spotify — client authenticates with HTTP Basic; refresh may or may not
//             return a new refresh token.

import { afterEach, describe, expect, it, vi } from "vitest";
import { createApp } from "../../src/core/app.ts";
import { allModules } from "../../src/modules/index.ts";
import { signTicket } from "../../src/core/protocol/tickets.ts";
import { sha256Hex } from "../../src/core/protocol/oauthConnect.ts";
import { readTokenObject } from "../../src/core/protocol/tokendoc.ts";
import { computeRequestSignature } from "../../src/core/protocol/hmac.ts";
import { utf8 } from "../../src/core/crypto/encoding.ts";
import { freshDocument, refreshDueTokens, refreshStoredToken } from "../../src/core/protocol/oauthRefresh.ts";
import type { TicketPayload } from "../../src/core/protocol/types.ts";
import type { OAuthProviderConfig } from "../../src/runtime/context.ts";
import { makeContext } from "../conformance/_harness.ts";

const EXTERNAL = "https://wh.example";
const CALLBACK = `${EXTERNAL}/v1/oauth/callback`;

// ── Fake provider token endpoint ────────────────────────────────────────────

interface Behaviour {
  tokenUrl: string;
  /** expires_in on every issued access token; null = omitted (non-expiring). */
  expiresIn: number | null;
  /** Whether the code exchange returns a refresh token. */
  issueRefresh: boolean;
  /** Whether a refresh returns (and switches to) a new refresh token. */
  rotate: boolean;
  /** HTTP status of an error answer (GitHub answers errors with 200). */
  errorStatus: number;
  /** Error code for an unknown/revoked refresh token. */
  badRefreshError: string;
  /** Client authentication the endpoint insists on. */
  auth: "post" | "basic";
  /** Send expires_in as a string (some providers do). */
  expiresAsString?: boolean;
}

class FakeProvider {
  readonly calls: Array<{ form: URLSearchParams; headers: Headers }> = [];
  readonly live = new Set<string>();
  private n = 0;
  down = false;
  /** Runs inside a refresh call before the provider answers (race tests). */
  beforeRefreshAnswer: (() => Promise<void>) | null = null;

  constructor(
    readonly b: Behaviour,
    readonly clientId: string,
    readonly clientSecret: string,
  ) {}

  private error(code: string, status = this.b.errorStatus): Response {
    return new Response(JSON.stringify({ error: code, error_description: "the provider says no (RT-leak)" }), { status });
  }

  private issue(withRefresh: boolean): Record<string, unknown> {
    this.n++;
    const out: Record<string, unknown> = { access_token: `AT-${this.n}`, token_type: "bearer", scope: "s1 s2" };
    if (this.b.expiresIn != null) out.expires_in = this.b.expiresAsString ? String(this.b.expiresIn) : this.b.expiresIn;
    if (withRefresh) {
      const rt = `RT-${this.n}`;
      this.live.add(rt);
      out.refresh_token = rt;
      out.refresh_token_expires_in = 15_897_600;
    }
    return out;
  }

  async handle(init: RequestInit | undefined): Promise<Response> {
    if (this.down) throw new TypeError("fetch failed");
    const form = new URLSearchParams(String(init?.body ?? ""));
    const headers = new Headers(init?.headers);
    this.calls.push({ form, headers });

    // Client authentication.
    if (this.b.auth === "basic") {
      const want = `Basic ${btoa(`${this.clientId}:${this.clientSecret}`)}`;
      if (headers.get("authorization") !== want || form.has("client_secret")) return this.error("invalid_client", 401);
    } else if (form.get("client_id") !== this.clientId || form.get("client_secret") !== this.clientSecret) {
      return this.error("invalid_client", this.b.errorStatus === 200 ? 200 : 401);
    }

    if (form.get("grant_type") === "authorization_code") {
      if (form.get("code") !== "good-code") return this.error(this.b.errorStatus === 200 ? "bad_verification_code" : "invalid_grant");
      return Response.json(this.issue(this.b.issueRefresh));
    }
    if (form.get("grant_type") === "refresh_token") {
      const rt = form.get("refresh_token") ?? "";
      if (!this.live.has(rt)) {
        if (this.beforeRefreshAnswer) await this.beforeRefreshAnswer();
        return this.error(this.b.badRefreshError);
      }
      if (this.beforeRefreshAnswer) await this.beforeRefreshAnswer();
      if (this.b.rotate) this.live.delete(rt);
      return Response.json(this.issue(this.b.rotate));
    }
    return this.error("unsupported_grant_type", 400);
  }
}

const GOOGLE: Behaviour = {
  tokenUrl: "https://oauth2.googleapis.com/token",
  expiresIn: 3599,
  issueRefresh: true,
  rotate: false,
  errorStatus: 400,
  badRefreshError: "invalid_grant",
  auth: "post",
};
const GITHUB_OAUTH_APP: Behaviour = {
  tokenUrl: "https://github.com/login/oauth/access_token",
  expiresIn: null,
  issueRefresh: false,
  rotate: false,
  errorStatus: 200,
  badRefreshError: "bad_refresh_token",
  auth: "post",
};
const GITHUB_APP: Behaviour = { ...GITHUB_OAUTH_APP, expiresIn: 28_800, issueRefresh: true, rotate: true };
const SPOTIFY: Behaviour = {
  tokenUrl: "https://accounts.spotify.com/api/token",
  expiresIn: 3600,
  issueRefresh: true,
  rotate: false,
  errorStatus: 400,
  badRefreshError: "invalid_grant",
  auth: "basic",
};

// ── Webhook under test ──────────────────────────────────────────────────────

afterEach(() => vi.unstubAllGlobals());

function setup(providers: Record<string, Behaviour>) {
  const hmac = crypto.getRandomValues(new Uint8Array(32)) as Uint8Array<ArrayBuffer>;
  const key = crypto.getRandomValues(new Uint8Array(32)) as Uint8Array<ArrayBuffer>;
  const ctx = makeContext({ hmacSecret: hmac, encryptionKey: key });
  ctx.config.externalUrl = EXTERNAL;
  const fakes: Record<string, FakeProvider> = {};
  const local: Record<string, OAuthProviderConfig> = {};
  for (const [name, b] of Object.entries(providers)) {
    fakes[name] = new FakeProvider(b, `${name}-client-id`, `${name}-client-secret`);
    local[name] = { clientSecret: `${name}-client-secret` };
  }
  ctx.config.oauthProviders = local;
  const fetchMock = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    const fake = Object.values(fakes).find((f) => f.b.tokenUrl === String(url));
    if (!fake) throw new Error(`unexpected fetch to ${String(url)}`);
    return fake.handle(init);
  });
  vi.stubGlobal("fetch", fetchMock);
  const app = createApp(ctx, allModules());

  const state = (provider: string, service: string, o: Partial<TicketPayload> = {}) =>
    signTicket(hmac, {
      sub: "u",
      svc: service,
      pur: "oauth_connect",
      prv: provider,
      tku: providers[provider]!.tokenUrl,
      clid: fakes[provider]!.clientId,
      rdu: CALLBACK,
      scp: "s1 s2",
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 600,
      nonce: crypto.randomUUID().replace(/-/g, ""),
      ...o,
    });

  /** The whole browser round trip: start (cookie) -> provider -> callback. */
  async function connect(provider: string, service: string, o: Partial<TicketPayload> = {}) {
    const st = await state(provider, service, o);
    const start = await app.request(`${EXTERNAL}/v1/oauth/start?${new URLSearchParams({ state: st })}`);
    expect(start.status).toBe(302);
    const authorize = new URL(start.headers.get("location")!);
    const cookie = start.headers.get("set-cookie")!.split(";")[0]!;
    const res = await app.request(`${EXTERNAL}/v1/oauth/callback?${new URLSearchParams({ code: "good-code", state: st })}`, {
      headers: { cookie },
    });
    const result = new URL(res.headers.get("location")!);
    return { authorize, result };
  }

  async function notify(service: string, refreshHint?: Record<string, string>) {
    const raw = JSON.stringify({ requestId: "req_1", service, reason: "manual_request", ...(refreshHint ? { refreshHint } : {}) });
    const ts = String(Math.floor(Date.now() / 1000));
    const sig = await computeRequestSignature(hmac, ts, utf8(raw));
    const res = await app.request(`${EXTERNAL}/v1/refresh-notify`, {
      method: "POST",
      body: raw,
      headers: {
        "content-type": "application/json",
        "X-TokenVault-Signature": `sha256=${sig}`,
        "X-TokenVault-Timestamp": ts,
        "X-TokenVault-Request-Id": crypto.randomUUID(),
      },
    });
    expect(res.status).toBe(200);
    return (await res.json()) as Record<string, unknown>;
  }

  /** An agent redeeming a TV-issued credential ticket at the webhook. */
  async function agentFetch(service: string, o: Partial<TicketPayload> = {}) {
    const ticket = await signTicket(hmac, {
      sub: "u",
      svc: service,
      pur: "agent_credential",
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 60,
      nonce: crypto.randomUUID().replace(/-/g, ""),
      ...o,
    });
    const res = await app.request(`${EXTERNAL}/v1/credential?${new URLSearchParams({ ticket, service })}`);
    return { status: res.status, body: (await res.json()) as { token?: Record<string, unknown>; error?: string } };
  }

  const token = async (service: string) => readTokenObject(key, (await ctx.storage.get("tokens", service))!);
  const meta = async (service: string) => (await ctx.storage.get("tokens", service))!.meta as Record<string, unknown>;

  /** Pretend time passed: the token now expires in `msLeft` (negative = expired). */
  async function expireIn(service: string, msLeft: number) {
    const doc = (await ctx.storage.get("tokens", service))!;
    (doc.meta as Record<string, unknown>).expiryTime = Date.now() + msLeft;
    await ctx.storage.set("tokens", service, doc);
  }

  return { ctx, app, fakes, fetchMock, connect, notify, agentFetch, token, meta, expireIn, state };
}

const refreshCalls = (f: FakeProvider) => f.calls.filter((c) => c.form.get("grant_type") === "refresh_token");

// ── Lifecycle ───────────────────────────────────────────────────────────────

describe("own-app lifecycle (Google)", () => {
  it("connect stores access + refresh token, expiry, the oauth hint and the creation id", async () => {
    const w = setup({ google: GOOGLE });
    const { authorize, result } = await w.connect("google", "gmail", { mode: "create", cid: "creation-1" });

    // Google only issues a refresh token with offline access + forced consent.
    expect(authorize.searchParams.get("access_type")).toBe("offline");
    expect(authorize.searchParams.get("prompt")).toBe("consent");
    expect(result.searchParams.get("status")).toBe("ok");

    const tok = await w.token("gmail");
    expect(tok.accessToken).toBe("AT-1");
    expect(tok.refreshToken).toBe("RT-1");
    expect(tok.hasRefreshToken).toBe(true);
    expect(tok.oauth).toEqual({ provider: "google", tokenUrl: GOOGLE.tokenUrl, clientId: "google-client-id" });
    expect(tok.creationId).toBe("creation-1");
    expect(Math.abs((tok.expiryTime as number) - (Date.now() + 3_599_000))).toBeLessThan(5_000);
  });

  it("the scheduled sweep refreshes a near-expiry token and leaves a fresh one alone", async () => {
    const w = setup({ google: GOOGLE });
    await w.connect("google", "gmail", { cid: "creation-1" });
    await w.connect("google", "calendar");

    // Fresh tokens: nothing to do.
    expect((await refreshDueTokens(w.ctx)).checked).toBe(0);
    expect(refreshCalls(w.fakes.google!)).toHaveLength(0);

    await w.expireIn("gmail", 5 * 60_000);
    const summary = await refreshDueTokens(w.ctx);
    expect(summary).toEqual({ checked: 1, refreshed: 1, failed: 0, skipped: 0 });

    const call = refreshCalls(w.fakes.google!)[0]!;
    expect(call.form.get("refresh_token")).toBe("RT-1");
    expect(call.form.get("client_id")).toBe("google-client-id");
    expect(call.form.get("client_secret")).toBe("google-client-secret");

    const tok = await w.token("gmail");
    expect(tok.accessToken).toBe("AT-3");
    // Google omits refresh_token on refresh: the old one is kept.
    expect(tok.refreshToken).toBe("RT-1");
    expect(tok.hasRefreshToken).toBe(true);
    expect(tok.expiryTime as number).toBeGreaterThan(Date.now() + 3_500_000);
    expect(typeof tok.lastRefreshed).toBe("string");
    // Metadata survives the refresh: the oauth hint (next refresh), the scope,
    // createdAt, and the creationId credential tickets are checked against.
    expect(tok.oauth).toEqual({ provider: "google", tokenUrl: GOOGLE.tokenUrl, clientId: "google-client-id" });
    expect(tok.creationId).toBe("creation-1");
    expect(typeof tok.createdAt).toBe("string");

    // The other credential was not touched.
    expect((await w.token("calendar")).accessToken).toBe("AT-2");
  });

  it("an auto-derived grant (cid ticket) still reads the credential after a refresh", async () => {
    const w = setup({ google: GOOGLE });
    await w.connect("google", "gmail", { cid: "creation-1" });
    expect((await w.notify("gmail")).status).toBe("refreshed");
    const got = await w.agentFetch("gmail", { cid: "creation-1" });
    expect(got.status).toBe(200);
    expect(got.body.token!.accessToken).toBe("AT-2");
  });

  it("manual refresh (TV's Refresh button) refreshes and reports the new expiry", async () => {
    const w = setup({ google: GOOGLE });
    await w.connect("google", "gmail");
    const out = await w.notify("gmail");
    expect(out.status).toBe("refreshed");
    expect(Date.parse(out.newExpiresAt as string)).toBeGreaterThan(Date.now() + 3_500_000);
    expect((await w.token("gmail")).accessToken).toBe("AT-2");
  });

  it("invalid_grant: reported as reconnect-required, credential untouched, sweep stops, reconnect clears it", async () => {
    const w = setup({ google: GOOGLE });
    await w.connect("google", "gmail");
    w.fakes.google!.live.clear(); // the user revoked access at Google

    const out = await w.notify("gmail");
    expect(out).toMatchObject({ status: "refresh_failed", error: "invalid_grant", reconnectRequired: true });
    // Never the provider's free text.
    expect(JSON.stringify(out)).not.toContain("RT-leak");

    const tok = await w.token("gmail");
    expect(tok.accessToken).toBe("AT-1");
    expect(tok.refreshToken).toBe("RT-1");
    expect(tok).toMatchObject({ refreshError: "invalid_grant", refreshReconnect: true });

    // The sweep does not hammer a dead grant every run.
    await w.expireIn("gmail", 60_000);
    const before = refreshCalls(w.fakes.google!).length;
    expect((await refreshDueTokens(w.ctx)).checked).toBe(0);
    expect(refreshCalls(w.fakes.google!)).toHaveLength(before);

    // Reconnecting replaces the token and clears the marker.
    await w.connect("google", "gmail");
    const after = await w.token("gmail");
    expect(after.refreshError).toBeUndefined();
    expect(after.refreshReconnect).toBeUndefined();
    await w.expireIn("gmail", 60_000);
    expect((await refreshDueTokens(w.ctx)).refreshed).toBe(1);
  });

  it("provider down: transient failure, credential untouched, the next sweep retries and clears the marker", async () => {
    const w = setup({ google: GOOGLE });
    await w.connect("google", "gmail");
    await w.expireIn("gmail", 60_000);
    w.fakes.google!.down = true;

    expect(await refreshDueTokens(w.ctx)).toMatchObject({ checked: 1, failed: 1 });
    expect(await w.token("gmail")).toMatchObject({
      accessToken: "AT-1",
      refreshError: "provider_unreachable",
      refreshReconnect: false,
    });

    w.fakes.google!.down = false;
    expect((await refreshDueTokens(w.ctx)).refreshed).toBe(1);
    const tok = await w.token("gmail");
    expect(tok.accessToken).toBe("AT-2");
    expect(tok.refreshError).toBeUndefined();
  });

  it("an agent fetching an expired token gets a freshly refreshed one", async () => {
    const w = setup({ google: GOOGLE });
    await w.connect("google", "gmail");
    await w.expireIn("gmail", -10 * 60_000);
    const got = await w.agentFetch("gmail");
    expect(got.status).toBe(200);
    expect(got.body.token!.accessToken).toBe("AT-2");
    expect(got.body.token!.expiryTime as number).toBeGreaterThan(Date.now());
  });

  it("a token still valid but inside the skew is served as-is; one background refresh, not one per request", async () => {
    const w = setup({ google: GOOGLE });
    await w.connect("google", "gmail");
    await w.expireIn("gmail", 30_000); // 30 s left: inside the 60 s skew, not expired
    const stored = (await w.ctx.storage.get("tokens", "gmail"))!;

    const tasks: Promise<unknown>[] = [];
    const run = (p: Promise<unknown>) => void tasks.push(p);
    const before = refreshCalls(w.fakes.google!).length;
    const a = await freshDocument(w.ctx, "gmail", stored, run);
    const b = await freshDocument(w.ctx, "gmail", stored, run);
    expect(a).toBe(stored); // answered immediately with the current document
    expect(b).toBe(stored);
    expect(tasks).toHaveLength(1); // second request found one already in flight

    await Promise.all(tasks);
    expect(refreshCalls(w.fakes.google!).length - before).toBe(1);
    expect((await w.token("gmail")).accessToken).toBe("AT-2");

    // The in-flight marker is cleared: a later near-expiry request can refresh again.
    await w.expireIn("gmail", 30_000);
    await freshDocument(w.ctx, "gmail", (await w.ctx.storage.get("tokens", "gmail"))!, run);
    expect(tasks).toHaveLength(2);
    await Promise.all(tasks);
  });

  it("a credential deleted while its refresh is in flight is not resurrected", async () => {
    const w = setup({ google: GOOGLE });
    await w.connect("google", "gmail");
    await w.expireIn("gmail", -60_000);
    const inner = w.ctx.storage;
    let gets = 0;
    // The delete lands right after the pre-write re-read: the window the old
    // read-then-set code left open.
    w.ctx.storage = {
      set: (c, k, d) => inner.set(c, k, d),
      delete: (c, k) => inner.delete(c, k),
      entries: (c) => inner.entries(c),
      count: (c) => inner.count(c),
      get: async (c, k) => {
        const doc = await inner.get(c, k);
        if (c === "tokens" && ++gets === 2) await inner.delete(c, k);
        return doc;
      },
      // Same contract as the real adapters: write only if still unchanged.
      setIfUnchanged: async (c, k, expected, data) => {
        const cur = await inner.get(c, k);
        if (!cur || JSON.stringify(cur) !== JSON.stringify(expected)) return false;
        await inner.set(c, k, data);
        return true;
      },
    };
    expect((await refreshStoredToken(w.ctx, "gmail")).status).toBe("no_token");
    expect(await inner.get("tokens", "gmail")).toBeNull();
  });

  it("an agent fetching a token inside the skew gets the current one without waiting for a refresh", async () => {
    const w = setup({ google: GOOGLE });
    await w.connect("google", "gmail");
    await w.expireIn("gmail", 30_000);
    const got = await w.agentFetch("gmail");
    expect(got.status).toBe(200);
    expect(got.body.token!.accessToken).toBe("AT-1");
  });

  it("a fetch-time refresh never hands over a credential replaced after the ticket check", async () => {
    const w = setup({ google: GOOGLE });
    await w.connect("google", "gmail", { cid: "old" });
    await w.expireIn("gmail", -10 * 60_000);
    const checked = (await w.ctx.storage.get("tokens", "gmail"))!;
    w.fakes.google!.beforeRefreshAnswer = async () => {
      w.fakes.google!.beforeRefreshAnswer = null;
      await w.connect("google", "gmail", { cid: "new" });
    };
    const served = await freshDocument(w.ctx, "gmail", checked);
    expect((served.meta as Record<string, unknown>).creationId).toBe("old");
  });

  it("an agent fetching an expired token whose refresh fails still gets what is stored", async () => {
    const w = setup({ google: GOOGLE });
    await w.connect("google", "gmail");
    await w.expireIn("gmail", -60_000);
    w.fakes.google!.down = true;
    const got = await w.agentFetch("gmail");
    expect(got.status).toBe(200);
    expect(got.body.token!.accessToken).toBe("AT-1");
  });

  it("a refresh racing another one that already rotated the token is not recorded as a failure", async () => {
    const w = setup({ google: { ...GOOGLE, rotate: true } });
    await w.connect("google", "gmail");
    const stale = (await w.ctx.storage.get("tokens", "gmail"))!;
    // A concurrent refresh wins first: RT-1 is spent, the store holds RT-2.
    expect((await w.notify("gmail")).status).toBe("refreshed");
    const winner = (await w.ctx.storage.get("tokens", "gmail"))!;
    // Our refresh started from the stale copy (RT-1): the provider refuses it.
    await w.ctx.storage.set("tokens", "gmail", stale);
    w.fakes.google!.beforeRefreshAnswer = async () => {
      await w.ctx.storage.set("tokens", "gmail", winner);
    };
    const out = await w.notify("gmail");
    expect(out.status).toBe("refreshed");
    const tok = await w.token("gmail");
    expect(tok.refreshToken).toBe("RT-2");
    expect(tok.refreshError).toBeUndefined();
  });

  it("a refresh never overwrites a token reconnected while it was at the provider", async () => {
    const w = setup({ google: GOOGLE });
    await w.connect("google", "gmail", { cid: "old" });
    w.fakes.google!.beforeRefreshAnswer = async () => {
      w.fakes.google!.beforeRefreshAnswer = null;
      await w.connect("google", "gmail", { cid: "new" });
    };
    expect((await w.notify("gmail")).status).toBe("refreshed");
    const tok = await w.token("gmail");
    expect(tok.creationId).toBe("new");
    expect(tok.accessToken).toBe("AT-2"); // the reconnect's token, not the refresh's AT-3
  });

  it("a pasted token without an oauth hint is never refreshed by the sweep", async () => {
    const w = setup({ google: GOOGLE });
    const { buildEncryptedTokenDocument } = await import("../../src/core/protocol/tokendoc.ts");
    const key = await w.ctx.secrets.encryptionKey();
    await w.ctx.storage.set(
      "tokens",
      "google",
      await buildEncryptedTokenDocument(key, "pasted-AT", "pasted-RT", { serviceName: "google", expiryTime: Date.now() + 1000 }),
    );
    expect((await refreshDueTokens(w.ctx)).checked).toBe(0);
    expect(w.fetchMock).not.toHaveBeenCalled();
  });
});

describe("GitHub", () => {
  it("OAuth App: no expiry and no refresh token; nothing to refresh, the token is served as is", async () => {
    const w = setup({ github: GITHUB_OAUTH_APP });
    const { result } = await w.connect("github", "gh");
    expect(result.searchParams.get("status")).toBe("ok");
    const tok = await w.token("gh");
    expect(tok.accessToken).toBe("AT-1");
    expect(tok.hasRefreshToken).toBe(false);
    expect(tok.expiryTime).toBeUndefined();

    expect((await w.notify("gh")).status).toBe("no_refresh_token");
    expect((await refreshDueTokens(w.ctx)).checked).toBe(0);
    expect((await w.agentFetch("gh")).body.token!.accessToken).toBe("AT-1");
    // GitHub needs Accept: application/json to answer in JSON.
    expect(w.fakes.github!.calls[0]!.headers.get("accept")).toBe("application/json");
  });

  it("GitHub App (expiring user tokens): 8 h expiry and the rotated refresh token is persisted every time", async () => {
    const w = setup({ github: GITHUB_APP });
    await w.connect("github", "gh");
    let tok = await w.token("gh");
    expect(tok.refreshToken).toBe("RT-1");
    expect(Math.abs((tok.expiryTime as number) - (Date.now() + 28_800_000))).toBeLessThan(5_000);

    await w.expireIn("gh", 60_000);
    expect((await refreshDueTokens(w.ctx)).refreshed).toBe(1);
    tok = await w.token("gh");
    expect(tok.accessToken).toBe("AT-2");
    expect(tok.refreshToken).toBe("RT-2");

    // The next refresh must use the rotated token (RT-1 is dead at GitHub).
    expect((await w.notify("gh")).status).toBe("refreshed");
    expect(refreshCalls(w.fakes.github!).map((c) => c.form.get("refresh_token"))).toEqual(["RT-1", "RT-2"]);
    expect((await w.token("gh")).refreshToken).toBe("RT-3");
  });

  it("an error answered with HTTP 200 is a failure, never an empty access token", async () => {
    const w = setup({ github: GITHUB_APP });
    await w.connect("github", "gh");
    w.fakes.github!.live.clear();
    const out = await w.notify("gh");
    expect(out).toMatchObject({ status: "refresh_failed", error: "bad_refresh_token", reconnectRequired: true });
    const tok = await w.token("gh");
    expect(tok.accessToken).toBe("AT-1");
    expect(tok.refreshToken).toBe("RT-1");
  });

  it("a bad code answered with HTTP 200 fails the connect and stores nothing", async () => {
    const w = setup({ github: GITHUB_OAUTH_APP });
    const st = await w.state("github", "gh");
    const start = await w.app.request(`${EXTERNAL}/v1/oauth/start?${new URLSearchParams({ state: st })}`);
    const cookie = start.headers.get("set-cookie")!.split(";")[0]!;
    const res = await w.app.request(`${EXTERNAL}/v1/oauth/callback?${new URLSearchParams({ code: "bad", state: st })}`, {
      headers: { cookie },
    });
    expect(new URL(res.headers.get("location")!).searchParams.get("code")).toBe("exchange_failed");
    expect(await w.ctx.storage.get("tokens", "gh")).toBeNull();
  });
});

describe("Spotify", () => {
  it("authenticates with HTTP Basic on the code exchange and on refresh", async () => {
    const w = setup({ spotify: SPOTIFY });
    const { result } = await w.connect("spotify", "music");
    expect(result.searchParams.get("status")).toBe("ok");
    const exchange = w.fakes.spotify!.calls[0]!;
    expect(exchange.headers.get("authorization")).toBe(`Basic ${btoa("spotify-client-id:spotify-client-secret")}`);
    expect(exchange.form.has("client_secret")).toBe(false);

    expect((await w.notify("music")).status).toBe("refreshed");
    const refresh = refreshCalls(w.fakes.spotify!)[0]!;
    expect(refresh.headers.get("authorization")).toMatch(/^Basic /);
    expect(refresh.form.has("client_secret")).toBe(false);
  });

  it("keeps the refresh token when the response omits one, stores it when it rotates", async () => {
    const w = setup({ spotify: SPOTIFY });
    await w.connect("spotify", "music");
    expect((await w.notify("music")).status).toBe("refreshed");
    expect((await w.token("music")).refreshToken).toBe("RT-1");

    w.fakes.spotify!.b.rotate = true;
    expect((await w.notify("music")).status).toBe("refreshed");
    expect((await w.token("music")).refreshToken).toBe("RT-3");
  });

  it("an operator can force client_secret_post (or basic) per provider", async () => {
    const w = setup({ spotify: { ...SPOTIFY, auth: "post" } });
    w.ctx.config.oauthProviders!.spotify!.tokenAuthMethod = "client_secret_post";
    expect((await w.connect("spotify", "music")).result.searchParams.get("status")).toBe("ok");
  });
});

describe("provider config", () => {
  it("expires_in sent as a string is understood", async () => {
    const w = setup({ google: { ...GOOGLE, expiresAsString: true } });
    await w.connect("google", "gmail");
    expect(Math.abs(((await w.token("gmail")).expiryTime as number) - (Date.now() + 3_599_000))).toBeLessThan(5_000);
  });

  it("operator authorizeParams are added but cannot replace the flow's own parameters", async () => {
    const w = setup({ google: GOOGLE });
    w.ctx.config.oauthProviders!.google!.authorizeParams = {
      login_hint: "me@example.com",
      redirect_uri: "https://evil.example/cb",
      code_challenge_method: "plain",
    };
    const { authorize } = await w.connect("google", "gmail");
    expect(authorize.searchParams.get("login_hint")).toBe("me@example.com");
    expect(authorize.searchParams.get("redirect_uri")).toBe(CALLBACK);
    expect(authorize.searchParams.get("code_challenge_method")).toBe("S256");
    expect(authorize.searchParams.get("access_type")).toBe("offline");
  });

  it("OAUTH_PROVIDERS_JSON provider names are matched case-insensitively", async () => {
    const { configFromEnv } = await import("../../src/runtime/config.ts");
    const env: Record<string, string> = {
      TOKENVAULT_FRONTEND_URL: "https://tokenvault.test",
      OAUTH_PROVIDERS_JSON: JSON.stringify({ Google: { clientSecret: "s" } }),
      OAUTH_REFRESH_WINDOW_SECONDS: "900",
    };
    const cfg = configFromEnv((k) => env[k]);
    expect(cfg.oauthProviders?.google?.clientSecret).toBe("s");
    expect(cfg.refreshWindowSeconds).toBe(900);
  });

  it("the sweep window is configurable", async () => {
    const w = setup({ google: GOOGLE });
    await w.connect("google", "gmail");
    await w.expireIn("gmail", 30 * 60_000);
    expect((await refreshDueTokens(w.ctx)).checked).toBe(0); // default window: 20 min
    w.ctx.config.refreshWindowSeconds = 3600;
    expect((await refreshDueTokens(w.ctx)).refreshed).toBe(1);
  });
});
