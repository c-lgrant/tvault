// Replay-guard helpers. The ReplayGuard interface itself lives in
// runtime/context.ts (it is an adapter); these are the protocol-level checks
// that turn a "seen before" result into the right error.

import { authFailed } from "./errors.ts";
import type { ReplayGuard } from "../../runtime/context.ts";

/**
 * Reject a missing or duplicate X-TokenVault-Request-Id (auth.py:54-58).
 * TV always sends this header; an absent ID cannot be replay-guarded and
 * is therefore rejected rather than silently allowed through.
 */
/**
 * Run the replay checks and a storage read concurrently (one round trip of
 * latency instead of three). Every promise is awaited to completion, so the
 * replay entries are always recorded. The read's result is returned only when
 * every check passed; otherwise the first failure (checks in the order given,
 * then the read) is thrown and the read result is discarded unused.
 */
export async function readAfterReplayChecks<T>(
  checks: Array<Promise<unknown>>,
  read: Promise<T>,
): Promise<T> {
  const settled = await Promise.allSettled([...checks, read]);
  for (const s of settled) {
    if (s.status === "rejected") throw s.reason;
  }
  return (settled[settled.length - 1] as PromiseFulfilledResult<T>).value;
}

export async function guardRequestId(
  replay: ReplayGuard,
  requestId: string | undefined,
): Promise<void> {
  if (!requestId) throw authFailed("Missing X-TokenVault-Request-Id header");
  if (await replay.checkRequestId(requestId)) {
    throw authFailed("Duplicate request ID");
  }
}
