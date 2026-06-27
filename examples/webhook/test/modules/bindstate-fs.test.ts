// Regression for the Copilot review: bindState stores under the internal "meta"
// collection. The Node FsStorageAdapter throws "Unknown collection" for any name
// it did not provision, so guardBound() -> isBound() must not break on Node.
// These tests exercise the REAL fs adapter (the test harness's MemoryStorage
// auto-creates collections and would have hidden the bug).

import { describe, expect, it } from "vitest";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FsStorageAdapter } from "../../src/adapters/storage/fs.ts";
import { isBound, markBound } from "../../src/modules/bindState.ts";

describe("bindState on the Node FS adapter (internal 'meta' collection)", () => {
  it("markBound/isBound round-trip without 'Unknown collection'", async () => {
    const path = join(tmpdir(), `tv-bindstate-${crypto.randomUUID()}.json`);
    const storage = await FsStorageAdapter.create(path);

    expect(await isBound(storage)).toBe(false);
    await markBound(storage);
    expect(await isBound(storage)).toBe(true);
  });

  it("persists bind state across adapter reloads", async () => {
    const path = join(tmpdir(), `tv-bindstate-${crypto.randomUUID()}.json`);
    const first = await FsStorageAdapter.create(path);
    await markBound(first);

    const reloaded = await FsStorageAdapter.create(path);
    expect(await isBound(reloaded)).toBe(true);
  });
});
