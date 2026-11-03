// Storage-path performance behaviour: audit lists are ordered/limited by the
// store, audit retention, the fs adapter's single-flight flush, atomic create,
// and the in-memory replay guard's eviction.

import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createApp } from "../../src/core/app.ts";
import { storageModule } from "../../src/modules/storage.ts";
import { D1StorageAdapter } from "../../src/adapters/storage/d1.ts";
import { FsStorageAdapter } from "../../src/adapters/storage/fs.ts";
import { MemoryReplayGuard } from "../../src/adapters/replay/memory.ts";
import { pruneAudit } from "../../src/core/protocol/retention.ts";
import { computeRequestSignature } from "../../src/core/protocol/hmac.ts";
import { utf8 } from "../../src/core/crypto/encoding.ts";
import type { StorageAdapter } from "../../src/runtime/context.ts";
import { makeContext } from "../conformance/_harness.ts";
import { FakeD1 } from "../runtime/_fakeD1.ts";

const secret = crypto.getRandomValues(new Uint8Array(32)) as Uint8Array<ArrayBuffer>;

async function storageCall(storage: StorageAdapter, body: Record<string, unknown>) {
  const ctx = { ...makeContext({ hmacSecret: secret }), storage };
  const app = createApp(ctx, [storageModule()]);
  const id = crypto.randomUUID();
  const raw = JSON.stringify({ ...body, attemptId: id });
  const ts = String(Math.floor(Date.now() / 1000));
  const sig = await computeRequestSignature(secret, ts, utf8(raw));
  const res = await app.request("/v1/storage", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "X-TokenVault-Signature": `sha256=${sig}`,
      "X-TokenVault-Timestamp": ts,
      "X-TokenVault-Request-Id": id,
    },
    body: raw,
  });
  const json = (await res.json()) as Record<string, unknown>;
  delete json.requestId;
  return json;
}

const stamp = (n: number) => `2026-01-0${n}T00:00:00Z`;

async function seedAudit(storage: StorageAdapter, n = 5) {
  for (let i = 1; i <= n; i++) await storage.set("audit", `evt-${i}`, { timestamp: stamp(i), action: i % 2 ? "read" : "write" });
  // A legacy row with no timestamp sorts last and is never pruned.
  await storage.set("audit", "evt-none", { action: "read" });
}

/** The same adapter with the store-side ordering hidden: forces the in-memory path. */
function withoutList(s: StorageAdapter): StorageAdapter {
  return { get: (c, k) => s.get(c, k), set: (c, k, d) => s.set(c, k, d), delete: (c, k) => s.delete(c, k), entries: (c) => s.entries(c), count: (c) => s.count(c) };
}

const dirs: string[] = [];
async function tmp(): Promise<string> {
  const d = await mkdtemp(join(tmpdir(), "tvwh-"));
  dirs.push(d);
  return d;
}
afterEach(async () => {
  vi.useRealTimers();
  await Promise.all(dirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

describe("audit list pushed into the store", () => {
  const pages = [
    { operation: "list", collection: "audit", options: { limit: 2 } },
    { operation: "list", collection: "audit", options: { limit: 2, after: stamp(4) } },
    { operation: "list", collection: "audit", options: { limit: 2, since: stamp(2) } },
    { operation: "list", collection: "audit", options: { limit: 10, since: stamp(2), after: stamp(5) } },
    { operation: "list_batch", collections: ["audit", "tokens"], options: { limit: 3 } },
  ];

  for (const [i, body] of pages.entries()) {
    it(`matches the in-memory result (case ${i})`, async () => {
      const db = new FakeD1();
      const d1 = await D1StorageAdapter.create(db as unknown as D1Database);
      await seedAudit(d1);
      const pushed = await storageCall(d1, body);
      const inMemory = await storageCall(withoutList(d1), body);
      expect(pushed).toEqual(inMemory);
    });
  }

  it("orders and limits in SQL instead of loading the collection", async () => {
    const db = new FakeD1();
    const d1 = await D1StorageAdapter.create(db as unknown as D1Database);
    await seedAudit(d1);
    db.log.length = 0;
    const res = (await storageCall(d1, { operation: "list", collection: "audit", options: { limit: 2 } })) as {
      items: Array<{ key: string }>;
      pagination: { hasMore: boolean; nextCursor: string; totalCount: number };
    };
    expect(res.items.map((i) => i.key)).toEqual(["evt-5", "evt-4"]);
    expect(res.pagination).toEqual({ hasMore: true, nextCursor: stamp(4), totalCount: 6 });
    expect(db.log.some((q) => q.includes("ORDER BY") && q.includes("LIMIT ?"))).toBe(true);
    expect(db.log.some((q) => q === "SELECT k, doc FROM kv WHERE collection = ?")).toBe(false);
  });

  it("works on the fs adapter too", async () => {
    const fs = await FsStorageAdapter.create(join(await tmp(), "kv.json"));
    await seedAudit(fs);
    for (const body of pages) {
      expect(await storageCall(fs, body)).toEqual(await storageCall(withoutList(fs), body));
    }
  });
});

describe("audit retention", () => {
  const now = Date.parse("2026-06-01T00:00:00Z");

  it("prunes events older than 90 days from D1 and keeps the rest", async () => {
    const db = new FakeD1();
    const d1 = await D1StorageAdapter.create(db as unknown as D1Database);
    await d1.set("audit", "old", { timestamp: "2026-01-01T00:00:00Z" });
    await d1.set("audit", "edge", { timestamp: "2026-03-05T00:00:00Z" }); // 88 days old
    await d1.set("audit", "new", { timestamp: "2026-05-31T00:00:00Z" });
    await d1.set("audit", "none", { action: "x" });
    await d1.set("tokens", "svc", { timestamp: "2020-01-01T00:00:00Z" }); // other collections untouched
    expect(await pruneAudit({ storage: d1 }, now)).toBe(0); // off by default: nothing deleted
    expect((await d1.entries("audit")).length).toBe(4);
    expect(await pruneAudit({ storage: d1 }, now, 90)).toBe(1);
    expect((await d1.entries("audit")).map(([k]) => k).sort()).toEqual(["edge", "new", "none"]);
    expect(await d1.get("tokens", "svc")).not.toBeNull();
  });

  it("prunes on the fs adapter and persists it", async () => {
    const path = join(await tmp(), "kv.json");
    const fs = await FsStorageAdapter.create(path);
    await fs.set("audit", "old", { timestamp: "2026-01-01T00:00:00Z" });
    await fs.set("audit", "new", { timestamp: "2026-05-31T00:00:00Z" });
    expect(await pruneAudit({ storage: fs, config: { auditRetentionDays: 90 } }, now)).toBe(1);
    const reloaded = await FsStorageAdapter.create(path);
    expect((await reloaded.entries("audit")).map(([k]) => k)).toEqual(["new"]);
  });
});

describe("fs adapter flush", () => {
  it("survives many concurrent writes: all persisted, no stray temp files", async () => {
    const dir = await tmp();
    const path = join(dir, "kv.json");
    const fs = await FsStorageAdapter.create(path);
    await Promise.all(Array.from({ length: 60 }, (_, i) => fs.set("tokens", `svc-${i}`, { n: i })));
    await fs.delete("tokens", "svc-0");
    const onDisk = JSON.parse(await readFile(path, "utf-8")) as { tokens: Record<string, unknown> };
    expect(Object.keys(onDisk.tokens)).toHaveLength(59);
    expect(onDisk.tokens["svc-59"]).toEqual({ n: 59 });
    expect((await readdir(dir)).filter((f) => f.endsWith(".tmp"))).toEqual([]);
  });

  it("a write resolves only after a flush that includes it", async () => {
    const path = join(await tmp(), "kv.json");
    const fs = await FsStorageAdapter.create(path);
    const first = fs.set("tokens", "a", { n: 1 });
    const second = fs.set("tokens", "b", { n: 2 }); // joins the in-flight flush
    await second;
    const onDisk = JSON.parse(await readFile(path, "utf-8")) as { tokens: Record<string, unknown> };
    expect(Object.keys(onDisk.tokens).sort()).toEqual(["a", "b"]);
    await first;
  });
});

describe("atomic create", () => {
  it("fs: of two simultaneous creates exactly one wins", async () => {
    const fs = await FsStorageAdapter.create(join(await tmp(), "kv.json"));
    const r = await Promise.all([fs.setIfAbsent("tokens", "x", { v: 1 }), fs.setIfAbsent("tokens", "x", { v: 2 })]);
    expect(r.sort()).toEqual([false, true]);
    expect(await fs.get("tokens", "x")).toEqual({ v: 1 });
  });

  it("D1: an existing key is refused and left untouched", async () => {
    const d1 = await D1StorageAdapter.create(new FakeD1() as unknown as D1Database);
    expect(await d1.setIfAbsent("tokens", "x", { v: 1 })).toBe(true);
    expect(await d1.setIfAbsent("tokens", "x", { v: 2 })).toBe(false);
    expect(await d1.get("tokens", "x")).toEqual({ v: 1 });
  });
});

describe("conditional write", () => {
  const adapters: Array<[string, () => Promise<StorageAdapter>]> = [
    ["D1", async () => D1StorageAdapter.create(new FakeD1() as unknown as D1Database)],
    ["fs", async () => FsStorageAdapter.create(join(await tmp(), "kv.json"))],
  ];
  for (const [name, make] of adapters) {
    it(`${name}: writes when unchanged, refuses after a delete or a replace`, async () => {
      const s = await make();
      await s.set("tokens", "x", { v: 1 });
      const read = (await s.get("tokens", "x"))!;
      expect(await s.setIfUnchanged!("tokens", "x", read, { v: 2 })).toBe(true);
      expect(await s.get("tokens", "x")).toEqual({ v: 2 });

      const read2 = (await s.get("tokens", "x"))!;
      await s.delete("tokens", "x");
      expect(await s.setIfUnchanged!("tokens", "x", read2, { v: 3 })).toBe(false);
      expect(await s.get("tokens", "x")).toBeNull(); // not resurrected

      await s.set("tokens", "x", { v: 4 });
      const read3 = (await s.get("tokens", "x"))!;
      await s.set("tokens", "x", { v: 5 }); // replaced by someone else
      expect(await s.setIfUnchanged!("tokens", "x", read3, { v: 6 })).toBe(false);
      expect(await s.get("tokens", "x")).toEqual({ v: 5 });
    });
  }
});

describe("MemoryReplayGuard eviction", () => {
  it("evicts expired entries from the oldest end, keeps live ones, re-records expired ids", async () => {
    vi.useFakeTimers();
    const guard = new MemoryReplayGuard();
    for (let i = 0; i < 6_000; i++) await guard.checkRequestId(`old-${i}`);
    vi.advanceTimersByTime(601_000); // all of those have expired
    for (let i = 0; i < 6_000; i++) await guard.checkRequestId(`live-${i}`); // crosses the cap: prune runs
    expect(await guard.checkRequestId("live-5999")).toBe(true); // still remembered
    expect(await guard.checkRequestId("old-0")).toBe(false); // expired, so unseen again
    expect(await guard.checkRequestId("old-0")).toBe(true); // and now recorded again
  });
});
