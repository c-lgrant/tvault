import { describe, expect, it } from "vitest";
import {
  BASELINE_SCHEMA_VERSION,
  CURRENT_SCHEMA_VERSION,
  applyPendingMigrations,
  applyPendingMigrationsWith,
} from "../../src/migrations/index.ts";
import type { StorageAdapter, StoredDocument } from "../../src/runtime/context.ts";

class MemStore implements StorageAdapter {
  private s = new Map<string, Map<string, StoredDocument>>();
  private c(n: string) { let m = this.s.get(n); if (!m) { m = new Map(); this.s.set(n, m); } return m; }
  async get(c: string, k: string) { return this.c(c).get(k) ?? null; }
  async set(c: string, k: string, d: StoredDocument) { this.c(c).set(k, d); }
  async delete(c: string, k: string) { this.c(c).delete(k); }
  async entries(c: string) { return [...this.c(c).entries()]; }
}

describe("applyPendingMigrations", () => {
  it("stamps schema_state to CURRENT on a fresh store", async () => {
    const s = new MemStore();
    const r = await applyPendingMigrations(s);
    expect(r.to).toBe(CURRENT_SCHEMA_VERSION);
    expect((await s.get("meta", "schema_state"))?.version).toBe(CURRENT_SCHEMA_VERSION);
  });

  it("is idempotent — second run is a no-op at the same version", async () => {
    const s = new MemStore();
    await applyPendingMigrations(s);
    const r2 = await applyPendingMigrations(s);
    expect(r2.from).toBe(CURRENT_SCHEMA_VERSION);
    expect(r2.to).toBe(CURRENT_SCHEMA_VERSION);
  });

  it("runs only steps with version greater than the stored version", async () => {
    const s = new MemStore();
    // Pretend the store is at version 0 (legacy, pre-mechanism).
    await s.set("meta", "schema_state", { version: 0 });
    const ran: number[] = [];
    const { applyPendingMigrationsWith } = await import("../../src/migrations/index.ts");
    await applyPendingMigrationsWith(s, [
      { version: 1, up: async () => { ran.push(1); } },
      { version: 2, up: async () => { ran.push(2); } },
    ], 2);
    expect(ran).toEqual([1, 2]);
    expect((await s.get("meta", "schema_state"))?.version).toBe(2);
  });

  it("never downgrades the stored stamp when current < from (Copilot review: no schema downgrade)", async () => {
    const s = new MemStore();
    // Simulate an older build redeployed: stored version is 5, but this build only knows up to 2.
    await s.set("meta", "schema_state", { version: 5 });
    const ran: number[] = [];
    const r = await applyPendingMigrationsWith(
      s,
      [
        { version: 1, up: async () => { ran.push(1); } },
        { version: 2, up: async () => { ran.push(2); } },
      ],
      2, // current = 2, stored = 5 → must NOT downgrade
    );
    // No steps should run (all steps are <= current=2 <= from=5)
    expect(ran).toEqual([]);
    // Stamp must NOT be downgraded from 5 to 2
    expect((await s.get("meta", "schema_state"))?.version).toBe(5);
    // Returned `to` must be the higher value (5, not 2)
    expect(r.to).toBe(5);
  });

  it("stampless store runs only steps above BASELINE, not zero steps (regression: absent stamp must use BASELINE not current)", async () => {
    // Bug scenario: a store that has NO schema_state stamp (set up before this
    // mechanism) with two steps [{version:1},{version:2}] targeting current=2.
    //
    // OLD (wrong) fallback=current: from=2 → pending=[] → 0 steps run. v2
    // step silently skipped even though the store was never migrated.
    //
    // NEW (correct) fallback=BASELINE=1: from=1 → pending=[{version:2}] → only
    // v2 runs. v1 was part of the baseline release and needs no catch-up.
    const s = new MemStore();
    // No schema_state written — stampless store.
    const ran: number[] = [];
    const { applyPendingMigrationsWith } = await import("../../src/migrations/index.ts");
    await applyPendingMigrationsWith(s, [
      { version: 1, up: async () => { ran.push(1); } },
      { version: 2, up: async () => { ran.push(2); } },
    ], 2);
    // Only v2 should run (from=BASELINE=1, pending = version>1).
    expect(ran).toEqual([2]);
    // Final stamp should be the target current=2.
    expect((await s.get("meta", "schema_state"))?.version).toBe(2);
    // Sanity-check the constant exported by the module.
    expect(BASELINE_SCHEMA_VERSION).toBe(1);
  });

  it("ignores a corrupted (NaN/Infinity/negative/non-integer) stamp and falls back to BASELINE", async () => {
    // A corrupted schema_state.version must not poison the migration logic.
    // NaN in particular would make `version > from` always false (silently
    // disabling all future migrations) and persist NaN via Math.max. The read
    // must reject it and fall back to BASELINE so catch-up steps still run.
    const { applyPendingMigrationsWith } = await import("../../src/migrations/index.ts");
    for (const bad of [Number.NaN, Infinity, -3, 1.5]) {
      const s = new MemStore();
      await s.set("meta", "schema_state", { version: bad });
      const ran: number[] = [];
      const r = await applyPendingMigrationsWith(s, [
        { version: 2, up: async () => { ran.push(2); } },
      ], 2);
      // Fell back to BASELINE=1 → the v2 step runs and the stamp is a clean int.
      expect(ran).toEqual([2]);
      expect(r.to).toBe(2);
      expect((await s.get("meta", "schema_state"))?.version).toBe(2);
    }
  });
});
