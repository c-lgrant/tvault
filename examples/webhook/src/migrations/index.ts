// Storage-schema migrations. Distinct from WEBHOOK_VERSION (the wire protocol):
// this is the version of the on-disk/D1 data model. On boot the webhook reads
// meta/schema_state.version and runs any MigrationStep newer than it, so new
// code reads older records from the SAME storage safely ("upconvert on load").
//
// v1 establishes the mechanism with NO steps (baseline). A future data-model
// change appends a step here and bumps CURRENT_SCHEMA_VERSION.

import type { StorageAdapter } from "../runtime/context.ts";

export const CURRENT_SCHEMA_VERSION = 1;

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
  // Absent stamp ⇒ a store created before this mechanism. A brand-new store is
  // indistinguishable here, but running zero pending steps and stamping CURRENT
  // is correct for both: a fresh store has no legacy records to convert, and a
  // pre-mechanism store at the current code version likewise needs none.
  return typeof v === "number" ? v : fallback;
}

export async function applyPendingMigrationsWith(
  storage: StorageAdapter,
  steps: MigrationStep[],
  current: number,
): Promise<{ from: number; to: number }> {
  const from = await storedVersion(storage, current);
  const pending = steps
    .filter((s) => s.version > from)
    .sort((a, b) => a.version - b.version);
  for (const step of pending) await step.up(storage);
  await storage.set(META, KEY, { version: current });
  return { from, to: current };
}

export function applyPendingMigrations(storage: StorageAdapter): Promise<{ from: number; to: number }> {
  return applyPendingMigrationsWith(storage, MIGRATIONS, CURRENT_SCHEMA_VERSION);
}
