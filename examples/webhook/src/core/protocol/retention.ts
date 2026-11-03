// Optional retention for the append-only `audit` collection. Off by default:
// audit events are the user's record and are never deleted unless
// AUDIT_RETENTION_DAYS is set to a positive number. Runs from the Workers cron
// trigger and from a Node timer.

import type { RuntimeContext } from "../../runtime/context.ts";

/** Delete audit events older than `days`; 0 (the default) keeps everything. Returns how many went. */
export async function pruneAudit(
  ctx: Pick<RuntimeContext, "storage"> & { rawStorage?: RuntimeContext["storage"]; config?: Pick<RuntimeContext["config"], "auditRetentionDays"> },
  now: number = Date.now(),
  days: number = ctx.config?.auditRetentionDays ?? 0,
): Promise<number> {
  if (!(days > 0)) return 0;
  const storage = ctx.rawStorage ?? ctx.storage;
  if (!storage.prune) return 0;
  // Same shape the control plane writes (second precision, trailing Z).
  const cutoff = new Date(now - days * 86_400_000).toISOString().replace(/\.\d{3}Z$/, "Z");
  const removed = await storage.prune("audit", cutoff, "timestamp");
  if (removed > 0) console.log(`[retention] pruned ${removed} audit events older than ${days} days`);
  return removed;
}
