// CacheReplayGuard unit tests. The Workers Cache API is injected as a fake so we
// can assert the dedup logic and the TTL encoding without a real edge cache.

import { describe, expect, it } from "vitest";
import { CacheReplayGuard, type ReplayCacheLike } from "../../src/adapters/replay/cache.ts";

function fakeCache(): ReplayCacheLike {
  const store = new Map<string, Response>();
  return {
    async match(req: Request) {
      return store.get(req.url);
    },
    async put(req: Request, res: Response) {
      store.set(req.url, res);
    },
  };
}

describe("CacheReplayGuard", () => {
  it("first sight of a request id is not a replay; the second is", async () => {
    const g = new CacheReplayGuard(fakeCache());
    expect(await g.checkRequestId("req_1")).toBe(false);
    expect(await g.checkRequestId("req_1")).toBe(true);
  });

  it("nonces dedup independently and are namespaced apart from request ids", async () => {
    const g = new CacheReplayGuard(fakeCache());
    expect(await g.checkNonce("v")).toBe(false);
    expect(await g.checkNonce("v")).toBe(true);
    // same raw value as a request id → different key prefix → NOT a replay
    expect(await g.checkRequestId("v")).toBe(false);
  });

  it("stores a cacheable entry whose max-age matches the per-kind TTL", async () => {
    let lastCacheControl: string | null = null;
    const cache: ReplayCacheLike = {
      async match() {
        return undefined;
      },
      async put(_req, res) {
        lastCacheControl = res.headers.get("Cache-Control");
      },
    };
    const g = new CacheReplayGuard(cache);
    await g.checkNonce("n1");
    expect(lastCacheControl).toBe("max-age=120");
    await g.checkRequestId("r1");
    expect(lastCacheControl).toBe("max-age=600");
  });

  // A stalled Cache API must not hang the request: the lookup counts as a
  // miss and the request goes on.
  it("treats a stalled match or put as unseen instead of hanging", async () => {
    const never = new Promise<never>(() => {});
    const stalled: ReplayCacheLike = {
      match: () => never,
      put: () => never,
    };
    const g = new CacheReplayGuard(stalled, 20);
    const started = Date.now();
    expect(await g.checkRequestId("req_stall")).toBe(false);
    expect(await g.checkNonce("n_stall")).toBe(false);
    expect(Date.now() - started).toBeLessThan(1000);
  });

  it("still reports a replay when the lookup answers in time", async () => {
    const g = new CacheReplayGuard(fakeCache(), 20);
    expect(await g.checkRequestId("req_2")).toBe(false);
    expect(await g.checkRequestId("req_2")).toBe(true);
  });
});
