// Bind-state flag. On the first successful /v1/exchange the webhook marks itself
// "bound" in durable storage. After that, /v1/register-url, /v1/exchange, and
// /bind are sealed — callers must supply x-tv-admin-secret (TV_ADMIN_SECRET) to
// re-run the setup flow.
//
// Collection "meta" is an INTERNAL_COLLECTIONS namespace: adapters provision it
// (so every runtime can read/write it), but it is excluded from KNOWN_COLLECTIONS
// so the agent-facing /v1/storage endpoint never exposes it. The flag is stored
// under the key "bind_state".

import type { StorageAdapter } from "../runtime/context.ts";

/**
 * Returns true once the first successful exchange has completed and the bind-
 * state flag is present in durable storage.
 */
export async function isBound(storage: StorageAdapter): Promise<boolean> {
  const doc = await storage.get("meta", "bind_state");
  return doc?.bound === true;
}

/**
 * Persist the bound flag. Called immediately after a successful /v1/exchange so
 * the flag is durable across isolate restarts and redeploys.
 */
export async function markBound(storage: StorageAdapter): Promise<void> {
  await storage.set("meta", "bind_state", { bound: true, boundAt: Date.now() });
}
