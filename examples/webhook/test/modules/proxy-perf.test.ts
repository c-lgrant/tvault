// /v1/proxy and /v1/credential hot-path behaviour: streamed upstream bodies, a
// timeout that covers response headers only, Server-Timing, and the ordering of
// replay checks against the storage read.

import { afterEach, describe, expect, it, vi } from "vitest";
import { createApp } from "../../src/core/app.ts";
import { credentialModule } from "../../src/modules/credential.ts";
import { proxyModule } from "../../src/modules/proxy.ts";
import { signTicket } from "../../src/core/protocol/tickets.ts";
import { computeRequestSignature } from "../../src/core/protocol/hmac.ts";
import { utf8 } from "../../src/core/crypto/encoding.ts";
import type { StorageAdapter } from "../../src/runtime/context.ts";
import type { TicketPayload } from "../../src/core/protocol/types.ts";
import { makeContext } from "../conformance/_harness.ts";

const secret = crypto.getRandomValues(new Uint8Array(32)) as Uint8Array<ArrayBuffer>;

function ticketPayload(overrides: Partial<TicketPayload> = {}): TicketPayload {
  return {
    sub: "u",
    svc: "github",
    pur: "proxy",
    iat: 1700000000,
    exp: 9999999999,
    nonce: crypto.randomUUID().replace(/-/g, ""),
    ...overrides,
  };
}

function setup() {
  const ctx = makeContext({ hmacSecret: secret });
  return { ctx, app: createApp(ctx, [proxyModule(), credentialModule()]) };
}

async function proxyCall(
  app: ReturnType<typeof createApp>,
  opts: { ticket?: string; requestId?: string; upstream?: Record<string, unknown> } = {},
) {
  const ticket = opts.ticket ?? (await signTicket(secret, ticketPayload()));
  const requestId = opts.requestId ?? crypto.randomUUID();
  const body = JSON.stringify({
    ticket,
    service: "github",
    attemptId: requestId,
    upstream: { url: "https://upstream.test/x", method: "GET", ...opts.upstream },
    headerTemplates: { Authorization: "Bearer ${TOKEN}" },
  });
  const ts = String(Math.floor(Date.now() / 1000));
  const sig = await computeRequestSignature(secret, ts, utf8(body));
  return app.request("/v1/proxy", {
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

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("proxy streaming", () => {
  it("delivers the upstream body incrementally, not buffered", async () => {
    const { ctx, app } = setup();
    await ctx.storage.set("tokens", "github", { accessToken: "tok" });

    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const stream = new ReadableStream<Uint8Array>({
      async start(controller) {
        controller.enqueue(utf8("first;"));
        await gate;
        controller.enqueue(utf8("second"));
        controller.close();
      },
    });
    vi.stubGlobal("fetch", async () => new Response(stream, { headers: { "content-type": "text/event-stream" } }));

    const res = await proxyCall(app);
    expect(res.status).toBe(200);
    expect(res.headers.get("x-upstream-status")).toBe("200");
    const reader = res.body!.getReader();
    // The first chunk is readable while the upstream has not finished.
    const first = await reader.read();
    expect(new TextDecoder().decode(first.value)).toBe("first;");
    release();
    const second = await reader.read();
    expect(new TextDecoder().decode(second.value)).toBe("second");
    expect((await reader.read()).done).toBe(true);
  });

  it("maps slow response headers to upstream_timeout", async () => {
    vi.useFakeTimers();
    const { ctx, app } = setup();
    await ctx.storage.set("tokens", "github", { accessToken: "tok" });
    let called!: () => void;
    const fetchCalled = new Promise<void>((r) => (called = r));
    vi.stubGlobal(
      "fetch",
      (_url: string, init: RequestInit) =>
        new Promise((_resolve, reject) => {
          called();
          init.signal!.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
        }),
    );

    const pending = proxyCall(app);
    await fetchCalled;
    await vi.advanceTimersByTimeAsync(30_001);
    const res = await pending;
    expect(res.status).toBe(504);
    expect(((await res.json()) as { error: string }).error).toBe("upstream_timeout");
    expect(res.headers.get("server-timing")).toMatch(/^tv-wh;dur=\d+\.\d$/);
  });

  it("does not abort a long body after quick headers", async () => {
    vi.useFakeTimers();
    const { ctx, app } = setup();
    await ctx.storage.set("tokens", "github", { accessToken: "tok" });
    let signal!: AbortSignal;
    vi.stubGlobal("fetch", async (_url: string, init: RequestInit) => {
      signal = init.signal!;
      return new Response(
        new ReadableStream<Uint8Array>({
          async start(controller) {
            controller.enqueue(utf8("a"));
            await new Promise((r) => setTimeout(r, 45_000)); // well past the 30 s header timeout
            controller.enqueue(utf8("b"));
            controller.close();
          },
        }),
      );
    });

    const res = await proxyCall(app);
    expect(res.status).toBe(200);
    const text = res.text();
    await vi.advanceTimersByTimeAsync(46_000);
    expect(await text).toBe("ab");
    expect(signal.aborted).toBe(false);
  });
});

describe("proxy Server-Timing", () => {
  it("appends tv-wh and tv-up after the upstream's own value", async () => {
    const { ctx, app } = setup();
    await ctx.storage.set("tokens", "github", { accessToken: "tok" });
    vi.stubGlobal("fetch", async () => new Response("ok", { headers: { "Server-Timing": "db;dur=5" } }));
    const res = await proxyCall(app);
    expect(res.headers.get("server-timing")).toMatch(/^db;dur=5, tv-wh;dur=\d+\.\d, tv-up;dur=\d+\.\d$/);
  });

  it("emits only tv-wh when the upstream fails", async () => {
    const { ctx, app } = setup();
    await ctx.storage.set("tokens", "github", { accessToken: "tok" });
    vi.stubGlobal("fetch", async () => {
      throw new TypeError("connect refused");
    });
    const res = await proxyCall(app);
    expect(((await res.json()) as { error: string }).error).toBe("upstream_error");
    expect(res.headers.get("server-timing")).toMatch(/^tv-wh;dur=\d+\.\d$/);
  });
});

describe("replay checks vs the storage read", () => {
  /** Storage that records reads and can hand back a credential. */
  function spyStorage(ctx: ReturnType<typeof makeContext>) {
    const inner = ctx.storage;
    const reads: string[] = [];
    const spy: StorageAdapter = {
      ...inner,
      get: async (c, k) => {
        reads.push(`${c}/${k}`);
        return inner.get(c, k);
      },
      set: (c, k, d) => inner.set(c, k, d),
      delete: (c, k) => inner.delete(c, k),
      entries: (c) => inner.entries(c),
      count: (c) => inner.count(c),
    };
    ctx.storage = spy;
    return reads;
  }

  it("refuses a replayed request id and never calls upstream", async () => {
    const { ctx, app } = setup();
    await ctx.storage.set("tokens", "github", { accessToken: "tok" });
    const upstream = vi.fn(async () => new Response("ok"));
    vi.stubGlobal("fetch", upstream);

    const id = crypto.randomUUID();
    expect((await proxyCall(app, { requestId: id })).status).toBe(200);
    const replay = await proxyCall(app, { requestId: id });
    expect(replay.status).toBe(401);
    expect(((await replay.json()) as { message: string }).message).toContain("Duplicate request ID");
    expect(upstream).toHaveBeenCalledTimes(1);
  });

  it("refuses a replayed ticket nonce and never calls upstream", async () => {
    const { ctx, app } = setup();
    await ctx.storage.set("tokens", "github", { accessToken: "tok" });
    const upstream = vi.fn(async () => new Response("ok"));
    vi.stubGlobal("fetch", upstream);

    const ticket = await signTicket(secret, ticketPayload());
    expect((await proxyCall(app, { ticket })).status).toBe(200);
    const replay = await proxyCall(app, { ticket });
    expect(replay.status).toBe(401);
    expect(((await replay.json()) as { error: string }).error).toBe("ticket_invalid");
    expect(upstream).toHaveBeenCalledTimes(1);
  });

  it("does not start the storage read when the ticket signature is bad", async () => {
    const { ctx, app } = setup();
    const reads = spyStorage(ctx);
    const good = await signTicket(secret, ticketPayload());
    const res = await proxyCall(app, { ticket: `${good.slice(0, -4)}0000` });
    expect(res.status).toBe(401);
    expect(reads).toEqual([]);
  });

  it("does not use the storage result when the credential nonce was replayed", async () => {
    const { ctx, app } = setup();
    await ctx.storage.set("tokens", "github", { accessToken: "tok" });
    const ticket = await signTicket(secret, ticketPayload({ pur: "agent_credential" }));
    const url = `/v1/credential?ticket=${encodeURIComponent(ticket)}&service=github`;
    const first = await app.request(url);
    expect(first.status).toBe(200);
    expect(await first.json()).toMatchObject({ token: { accessToken: "tok" } });
    const replay = await app.request(url);
    expect(replay.status).toBe(401);
    expect(await replay.json()).not.toHaveProperty("token");
  });

  it("runs the nonce check, request-id check and storage read concurrently", async () => {
    const { ctx, app } = setup();
    await ctx.storage.set("tokens", "github", { accessToken: "tok" });
    const events: string[] = [];
    const rid = ctx.replay.checkRequestId.bind(ctx.replay);
    const nonce = ctx.replay.checkNonce.bind(ctx.replay);
    ctx.replay.checkRequestId = async (id) => {
      events.push("rid:start");
      await Promise.resolve();
      const r = await rid(id);
      events.push("rid:end");
      return r;
    };
    ctx.replay.checkNonce = async (n, ttl) => {
      events.push("nonce:start");
      await Promise.resolve();
      const r = await nonce(n, ttl);
      events.push("nonce:end");
      return r;
    };
    const inner = ctx.storage;
    ctx.storage = { ...inner, get: async (c, k) => (events.push("get:start"), inner.get(c, k)), set: inner.set, delete: inner.delete, entries: inner.entries, count: inner.count };
    vi.stubGlobal("fetch", async () => new Response("ok"));

    const fresh = createApp(ctx, [proxyModule()]);
    expect((await proxyCall(fresh)).status).toBe(200);
    const firstEnd = events.findIndex((e) => e.endsWith(":end"));
    expect(events.slice(0, firstEnd).sort()).toEqual(["get:start", "nonce:start", "rid:start"]);
  });
});
