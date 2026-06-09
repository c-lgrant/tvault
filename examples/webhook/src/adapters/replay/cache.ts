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

import type { ReplayGuard } from "../../runtime/context.ts";

const REQUEST_ID_TTL_S = 600;
const NONCE_TTL_S = 120;

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
  constructor(private readonly cache: ReplayCacheLike = defaultCache()) {}

  private async checkAndAdd(kind: string, value: string, ttlSeconds: number): Promise<boolean> {
    const key = new Request(`${KEY_ORIGIN}/${kind}/${encodeURIComponent(value)}`);
    if (await this.cache.match(key)) return true;
    // GET key + 200 + a max-age Cache-Control = a cacheable response.
    await this.cache.put(key, new Response("1", { headers: { "Cache-Control": `max-age=${ttlSeconds}` } }));
    return false;
  }

  async checkRequestId(id: string): Promise<boolean> {
    return this.checkAndAdd("rid", id, REQUEST_ID_TTL_S);
  }

  async checkNonce(nonce: string): Promise<boolean> {
    return this.checkAndAdd("nonce", nonce, NONCE_TTL_S);
  }
}
