// One-time boot routine, awaited before the app serves its first request. Runs
// once per process (Node) / once per isolate cold-start (Workers).
//
//  1. Upconvert storage to the current schema (safe no-op when already current).
//  2. Auto-seal: an already-configured webhook that already holds credentials but
//     has no bind_state is one that was set up before the seal shipped. Seal it on
//     boot so its setup endpoints aren't briefly open after an upgrade. A fresh
//     seeded webhook (no tokens yet) is left unbound so first /v1/exchange works.

import type { RuntimeContext } from "./context.ts";
import { applyPendingMigrations } from "../migrations/index.ts";
import { isBound, markBound } from "../modules/bindState.ts";

export async function runStartup(ctx: RuntimeContext): Promise<void> {
  await applyPendingMigrations(ctx.storage);

  // Auto-seal is best-effort: a failure to write the bind flag must never
  // prevent the webhook from serving. Migration above is intentionally outside
  // this block — serving on an un-upconverted store is worse than not sealing.
  try {
    if (await isBound(ctx.storage)) return;
    if (!(await ctx.secrets.isConfigured())) return;
    const tokens = await ctx.storage.entries("tokens");
    if (tokens.length > 0) await markBound(ctx.storage);
  } catch (e) {
    console.warn("[startup] auto-seal failed (non-fatal):", e);
  }
}
