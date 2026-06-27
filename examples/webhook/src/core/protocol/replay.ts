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
export async function guardRequestId(
  replay: ReplayGuard,
  requestId: string | undefined,
): Promise<void> {
  if (!requestId) throw authFailed("Missing X-TokenVault-Request-Id header");
  if (await replay.checkRequestId(requestId)) {
    throw authFailed("Duplicate request ID");
  }
}
