// Workers KV replay guard. Request IDs (10 min) and ticket nonces (2 min) are
// recorded with KV's native expirationTtl. KV is eventually consistent, so this
// is best-effort across isolates/regions — a tiny replay window can exist under
// concurrent edge hits. The ticket's own `exp` and the HMAC timestamp window
// remain the primary freshness bounds; this guard is defence-in-depth.

import type { ReplayGuard } from "../../runtime/context.ts";

const REQUEST_ID_TTL_S = 600;
const NONCE_TTL_S = 120;

export class KvReplayGuard implements ReplayGuard {
  constructor(private readonly kv: KVNamespace) {}

  private async checkAndAdd(key: string, ttlSeconds: number): Promise<boolean> {
    const seen = await this.kv.get(key);
    if (seen !== null) return true;
    await this.kv.put(key, "1", { expirationTtl: ttlSeconds });
    return false;
  }

  async checkRequestId(id: string): Promise<boolean> {
    return this.checkAndAdd(`rid:${id}`, REQUEST_ID_TTL_S);
  }

  async checkNonce(nonce: string): Promise<boolean> {
    return this.checkAndAdd(`nonce:${nonce}`, NONCE_TTL_S);
  }
}
