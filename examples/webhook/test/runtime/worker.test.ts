// The Workers entry point builds the app once per isolate. On Workers, I/O
// belongs to the request that started it: if that request is cancelled while
// the build's D1 calls are in flight, the build never settles. A later request
// must therefore never await a build that another request started — it would
// hang until its client gave up (the 2026-10-13 "tvault get times out" bug).

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FakeD1 } from "./_fakeD1.ts";

const SEED = "a".repeat(64);

const envFor = (db: FakeD1) => ({
  DB: db as unknown as D1Database,
  TV_WEBHOOK_SEED: SEED,
  TOKENVAULT_FRONTEND_URL: "https://tokenvault.test",
});

function within<T>(p: Promise<T>, ms: number): Promise<T> {
  return Promise.race([
    p,
    new Promise<T>((_, reject) => setTimeout(() => reject(new Error(`still pending after ${ms} ms`)), ms)),
  ]);
}

async function loadWorker() {
  vi.resetModules(); // fresh module state = a fresh isolate
  return (await import("../../src/runtime/worker.ts")).default;
}

const execCtx = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;

describe("worker entry point", () => {
  beforeEach(() => {
    const cache = new Map<string, Response>();
    vi.stubGlobal("caches", {
      default: {
        match: async (r: Request) => cache.get(r.url)?.clone(),
        put: async (r: Request, res: Response) => void cache.set(r.url, res),
      },
    });
  });
  afterEach(() => vi.unstubAllGlobals());

  it("serves a request while another request's startup is stuck", async () => {
    const worker = await loadWorker();
    const db = new FakeD1();
    const env = envFor(db);

    db.hold(); // the first request's startup never completes (its request was cancelled)
    void worker.fetch(new Request("https://wh.test/v1/health", { method: "HEAD" }), env, execCtx);

    const res = await within(worker.fetch(new Request("https://wh.test/v1/health"), env, execCtx), 2000);
    expect(res.status).toBe(200);
    db.release();
  });

  it("builds the app once and reuses it", async () => {
    const worker = await loadWorker();
    const db = new FakeD1();
    const env = envFor(db);

    for (let i = 0; i < 3; i++) {
      const res = await worker.fetch(new Request("https://wh.test/v1/health"), env, execCtx);
      expect(res.status).toBe(200);
    }
    // The table is created only because it was missing (the two parallel startup
    // reads may each create it: the statement is idempotent), and never again.
    const creates = () => db.log.filter((q) => q.startsWith("CREATE TABLE")).length;
    expect(creates()).toBeGreaterThanOrEqual(1);
    expect(creates()).toBeLessThanOrEqual(2);
  });

  it("does not issue CREATE TABLE when the schema already exists", async () => {
    const db = new FakeD1();
    db.tableExists = true;
    const res = await (await loadWorker()).fetch(new Request("https://wh.test/v1/health"), envFor(db), execCtx);
    expect(res.status).toBe(200);
    expect(db.log.filter((q) => q.startsWith("CREATE TABLE"))).toEqual([]);
  });

  it("retries startup on the next request after a failure", async () => {
    const worker = await loadWorker();
    const db = new FakeD1();
    const env = envFor(db);

    db.fail(2); // both startup reads (bind state + schema stamp) fail
    await expect(worker.fetch(new Request("https://wh.test/v1/health"), env, execCtx)).rejects.toThrow();
    const res = await worker.fetch(new Request("https://wh.test/v1/health"), env, execCtx);
    expect(res.status).toBe(200);
  });

  it("does not write to D1 when an already-current webhook cold-starts", async () => {
    const db = new FakeD1();
    const env = envFor(db);
    await (await loadWorker()).fetch(new Request("https://wh.test/v1/health"), env, execCtx); // first boot stamps
    db.log.length = 0;

    await (await loadWorker()).fetch(new Request("https://wh.test/v1/health"), env, execCtx); // next isolate
    expect(db.log.filter((q) => q.startsWith("INSERT"))).toEqual([]);
  });

  it("the cron trigger refreshes a due own-app OAuth token", async () => {
    const { D1StorageAdapter } = await import("../../src/adapters/storage/d1.ts");
    const { seedDerivedSecrets } = await import("../../src/adapters/secrets/seedDerived.ts");
    const { buildEncryptedTokenDocument, readTokenObject } = await import("../../src/core/protocol/tokendoc.ts");
    const db = new FakeD1();
    const storage = await D1StorageAdapter.create(db as unknown as D1Database);
    const key = await seedDerivedSecrets(SEED).encryptionKey();
    const tokenUrl = "https://oauth2.googleapis.com/token";
    await storage.set(
      "tokens",
      "gmail",
      await buildEncryptedTokenDocument(key, "old-AT", "the-RT", {
        serviceName: "gmail",
        oauth: { provider: "google", tokenUrl, clientId: "cid" },
        expiryTime: Date.now() + 60_000,
      }),
    );
    const fetchMock = vi.fn(async () => Response.json({ access_token: "new-AT", expires_in: 3599 }));
    vi.stubGlobal("fetch", fetchMock);

    const worker = await loadWorker();
    const env = { ...envFor(db), OAUTH_PROVIDERS_JSON: JSON.stringify({ google: { clientSecret: "s" } }) };
    await worker.scheduled!({} as ScheduledController, env, execCtx);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const tok = await readTokenObject(key, (await storage.get("tokens", "gmail"))!);
    expect(tok.accessToken).toBe("new-AT");
    expect(tok.refreshToken).toBe("the-RT");
  });
});
