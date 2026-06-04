// Replay-guard helpers. The ReplayGuard interface itself lives in
// runtime/context.ts (it is an adapter); these are the protocol-level checks
// that turn a "seen before" result into the right error.

import { authFailed } from "./errors.ts";
import type { ReplayGuard } from "../../runtime/context.ts";

/** Reject a duplicate X-TokenVault-Request-Id (auth.py:54-58). */
export async function guardRequestId(
  replay: ReplayGuard,
  requestId: string | undefined,
): Promise<void> {
  if (requestId && (await replay.checkRequestId(requestId))) {
    throw authFailed("Duplicate request ID");
  }
}
