// Ticket nonces recorded in the storage adapter with an atomic insert, so a
// one-shot ticket is one-shot everywhere: two requests with the same nonce can
// never both pass, whichever colo or process they land on. The per-colo cache
// guard (cache.ts) cannot promise that.
//
// Request ids stay with the inner guard: a request is already bound by the HMAC
// timestamp window, and it is the ticket that authorises a credential read.
//
// A storage failure rejects the check, so the request fails; it is never
// treated as "nonce not seen".

import { NONCE_COLLECTION, type ReplayGuard, type StorageAdapter } from "../../runtime/context.ts";

const NONCE_TTL_S = 120;

type AtomicStorage = StorageAdapter & Required<Pick<StorageAdapter, "setIfAbsent">>;

export class StoredNonceGuard implements ReplayGuard {
  constructor(
    private readonly storage: AtomicStorage,
    private readonly inner: ReplayGuard,
  ) {}

  checkRequestId(id: string): Promise<boolean> {
    return this.inner.checkRequestId(id);
  }

  private lastPrune = Date.now();

  async checkNonce(nonce: string, ttlSeconds: number = NONCE_TTL_S): Promise<boolean> {
    const now = Date.now();
    const exp = new Date(now + ttlSeconds * 1000).toISOString();
    // An expired row that has not been pruned yet still counts as seen: the
    // ticket it belonged to has expired too.
    const seen = !(await this.storage.setIfAbsent(NONCE_COLLECTION, nonce, { exp }));
    // The cron trigger prunes too, but a Worker deployed before the trigger
    // existed has none in its wrangler.toml. So the guard also prunes by
    // itself, at most once per interval per isolate. A failed prune never
    // fails the request: the nonce is already recorded.
    if (now - this.lastPrune >= PRUNE_INTERVAL_MS) {
      this.lastPrune = now;
      await pruneNonces(this.storage, now).catch(() => console.error("[replay] nonce prune failed"));
    }
    return seen;
  }
}

/** How often one isolate deletes expired nonce rows by itself. */
export const PRUNE_INTERVAL_MS = 10 * 60 * 1000;

/** Delete nonce rows past their expiry. Returns how many went. */
export async function pruneNonces(storage: StorageAdapter, now: number = Date.now()): Promise<number> {
  if (!storage.prune) return 0;
  return storage.prune(NONCE_COLLECTION, new Date(now).toISOString(), "exp");
}
