// Retention for the append-only `audit` collection. Nothing else deletes audit
// events, so without this the collection (and every list over it) only grows.
// Runs from the Workers cron trigger and from a Node timer.

import type { RuntimeContext } from "../../runtime/context.ts";

export const AUDIT_RETENTION_DAYS = 90;

/** Delete audit events older than the retention window; returns how many went. */
export async function pruneAudit(
  ctx: Pick<RuntimeContext, "storage"> & { rawStorage?: RuntimeContext["storage"] },
  now: number = Date.now(),
  days: number = AUDIT_RETENTION_DAYS,
): Promise<number> {
  const storage = ctx.rawStorage ?? ctx.storage;
  if (!storage.prune) return 0;
  // Same shape the control plane writes (second precision, trailing Z).
  const cutoff = new Date(now - days * 86_400_000).toISOString().replace(/\.\d{3}Z$/, "Z");
  const removed = await storage.prune("audit", cutoff, "timestamp");
  if (removed > 0) console.log(`[retention] pruned ${removed} audit events older than ${days} days`);
  return removed;
}
