// Storage-schema migrations. Distinct from WEBHOOK_VERSION (the wire protocol):
// this is the version of the on-disk/D1 data model. On boot the webhook reads
// meta/schema_state.version and runs any MigrationStep newer than it, so new
// code reads older records from the SAME storage safely ("upconvert on load").
//
// v1 establishes the mechanism with NO steps (baseline). A future data-model
// change appends a step here and bumps CURRENT_SCHEMA_VERSION.

import type { StorageAdapter } from "../runtime/context.ts";

/** The schema version at which the migration mechanism itself shipped. */
export const BASELINE_SCHEMA_VERSION = 1;

export const CURRENT_SCHEMA_VERSION = 1;

/**
 * A single schema migration step.
 *
 * Contract for every `up` implementation:
 *  - **Idempotent.** A step may re-run if the process crashes after it executes
 *    but before the final `schema_state` stamp is written. It must produce the
 *    same result whether run once or multiple times.
 *  - **Empty-store safe.** Steps iterate existing records; a fresh store has
 *    none, so `up` must be a no-op when the store is empty.
 */
export interface MigrationStep {
  version: number;
  up(storage: StorageAdapter): Promise<void>;
}

export const MIGRATIONS: MigrationStep[] = [];

const META = "meta";
const KEY = "schema_state";

async function storedVersion(storage: StorageAdapter, fallback: number): Promise<number> {
  const doc = await storage.get(META, KEY);
  const v = doc?.version;
  // Absent stamp ⇒ "never migrated". We treat it as BASELINE_SCHEMA_VERSION
  // (not `current`) so every step whose version is > baseline will run. This
  // is correct for both cases an absent stamp can represent:
  //   • A store set up before this mechanism shipped — may need catch-up steps.
  //   • A brand-new empty store — steps iterate existing records and are no-ops.
  // Using `current` as the fallback would silently skip needed steps whenever a
  // stale store jumps to a future release where CURRENT_SCHEMA_VERSION > 1.
  // Validate as a finite, non-negative integer. A corrupted stamp (NaN,
  // Infinity, negative, or non-numeric) must not propagate: NaN in particular
  // would poison `Math.max(from, current)` and make every `version > from`
  // filter false, silently disabling all future migrations. Fall back instead.
  return typeof v === "number" && Number.isInteger(v) && v >= 0 ? v : fallback;
}

/**
 * Applies any pending migration steps and stamps the schema version.
 *
 * **Never downgrades the stored stamp.** If the store already records a
 * version higher than `current` (e.g. an operator temporarily redeploys an
 * older build), the stamp is left at `from` and no steps are run. This
 * prevents wrongly re-running migrations against already-upconverted data on
 * the next forward deployment.
 */
export async function applyPendingMigrationsWith(
  storage: StorageAdapter,
  steps: MigrationStep[],
  current: number,
): Promise<{ from: number; to: number }> {
  const from = await storedVersion(storage, BASELINE_SCHEMA_VERSION);
  // Never stamp below the already-recorded version (guard against older builds
  // redeployed temporarily then re-upgraded).
  const to = Math.max(from, current);
  const pending = steps
    .filter((s) => s.version > from && s.version <= current)
    .sort((a, b) => a.version - b.version);
  for (const step of pending) await step.up(storage);
  await storage.set(META, KEY, { version: to });
  return { from, to };
}

export function applyPendingMigrations(storage: StorageAdapter): Promise<{ from: number; to: number }> {
  return applyPendingMigrationsWith(storage, MIGRATIONS, CURRENT_SCHEMA_VERSION);
}
