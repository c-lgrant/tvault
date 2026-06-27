// In-memory replay guard for the Node runtime. TTL windows match the reference:
// request IDs 10 min, ticket nonces 2 min. A single long-lived process keeps
// the maps; bounded with a lazy prune so they can't grow without limit.

import type { ReplayGuard } from "../../runtime/context.ts";

const MAX_ENTRIES = 10_000;

class TtlSet {
  private readonly entries = new Map<string, number>();
  constructor(private readonly ttlMs: number) {}

  /** Record `value`; return true if it was already present and unexpired. */
  checkAndAdd(value: string): boolean {
    const now = Date.now();
    const expiry = this.entries.get(value);
    if (expiry !== undefined && expiry > now) return true;
    this.entries.set(value, now + this.ttlMs);
    if (this.entries.size > MAX_ENTRIES) this.prune(now);
    return false;
  }

  private prune(now: number): void {
    for (const [k, exp] of this.entries) {
      if (exp <= now) this.entries.delete(k);
    }
  }
}

export class MemoryReplayGuard implements ReplayGuard {
  private readonly requestIds = new TtlSet(600_000);
  private readonly nonces = new TtlSet(120_000);

  async checkRequestId(id: string): Promise<boolean> {
    return this.requestIds.checkAndAdd(id);
  }

  async checkNonce(nonce: string): Promise<boolean> {
    return this.nonces.checkAndAdd(nonce);
  }
}
