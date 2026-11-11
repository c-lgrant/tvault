// Cloudflare Workers replay guard backed by the per-colo Cache API.
//
// Request IDs (10 min) and ticket nonces (2 min) are recorded as cached
// responses whose `Cache-Control: max-age` matches the TTL. The Cache API is
// per-colo and best-effort — entries are NOT shared across colos and can be
// evicted under memory pressure — so this is deliberately defence-in-depth, not
// a hard guarantee. The primary freshness bounds are the ticket's own `exp`
// (TV mints 60-second tickets) and the HMAC timestamp window; a replay only
// slips this guard if it arrives within that short window AND lands on a
// different/cold colo. The win over KV: no daily write quota.
//
// `caches.default` is injected via the constructor so tests can supply a fake.
//
// Each Cache API call is bounded. The Cache API can stall: a traced request
// spent 2.3 s in cache.match (it ended as a 504 MISS) until TV's 3 s timeout
// cancelled it, with ~0 ms CPU. A stalled lookup is treated as a miss, like
// the evictions this guard already tolerates, so a slow cache cannot hang
// every credential read and write.

import type { ReplayGuard } from "../../runtime/context.ts";

const REQUEST_ID_TTL_S = 600;
const NONCE_TTL_S = 120;
const CACHE_OP_TIMEOUT_MS = 300;

const TIMED_OUT = Symbol("timed out");

async function bounded<T>(op: Promise<T>, ms: number): Promise<T | typeof TIMED_OUT> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<typeof TIMED_OUT>((resolve) => {
    timer = setTimeout(() => resolve(TIMED_OUT), ms);
  });
  try {
    return await Promise.race([op, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

// Synthetic, non-routable origin for cache keys — the URL is never fetched; it
// only namespaces replay entries inside this Worker's cache.
const KEY_ORIGIN = "https://replay.tv-webhook.internal";

/** The slice of the Cache API this guard needs (so tests can fake it). */
export interface ReplayCacheLike {
  match(request: Request): Promise<Response | undefined>;
  put(request: Request, response: Response): Promise<void>;
}

// `caches.default` is a Cloudflare extension; the `WebWorker` lib's CacheStorage
// type doesn't declare it, so reach it through a narrow structural cast.
const defaultCache = (): ReplayCacheLike => (caches as unknown as { default: ReplayCacheLike }).default;

export class CacheReplayGuard implements ReplayGuard {
  constructor(
    private readonly cache: ReplayCacheLike = defaultCache(),
    private readonly timeoutMs: number = CACHE_OP_TIMEOUT_MS,
  ) {}

  private async checkAndAdd(kind: string, value: string, ttlSeconds: number): Promise<boolean> {
    const key = new Request(`${KEY_ORIGIN}/${kind}/${encodeURIComponent(value)}`);
    const hit = await bounded(this.cache.match(key), this.timeoutMs);
    if (hit === TIMED_OUT) {
      console.warn(`[replay] cache match took over ${this.timeoutMs}ms; treating this ${kind} as unseen`);
    } else if (hit) {
      return true;
    }
    // GET key + 200 + a max-age Cache-Control = a cacheable response.
    const put = this.cache.put(key, new Response("1", { headers: { "Cache-Control": `max-age=${ttlSeconds}` } }));
    if ((await bounded(put, this.timeoutMs)) === TIMED_OUT) {
      console.warn(`[replay] cache put took over ${this.timeoutMs}ms; this ${kind} may not be recorded`);
    }
    return false;
  }

  async checkRequestId(id: string): Promise<boolean> {
    return this.checkAndAdd("rid", id, REQUEST_ID_TTL_S);
  }

  async checkNonce(nonce: string, ttlSeconds: number = NONCE_TTL_S): Promise<boolean> {
    return this.checkAndAdd("nonce", nonce, ttlSeconds);
  }
}
