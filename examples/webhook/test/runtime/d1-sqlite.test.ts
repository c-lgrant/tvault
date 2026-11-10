// Runs the D1 adapter's real SQL (put/get/delete/prune and the conditional
// writes) against an actual SQLite engine. FakeD1 pattern-matches statements in
// JS, so a typo in the adapter's SQL would pass there; here SQLite parses it.
// `node:sqlite` ships with Node 22+, so no dependency is added.

import { createRequire } from "node:module";
import { beforeEach, describe, expect, it } from "vitest";
import { D1StorageAdapter } from "../../src/adapters/storage/d1.ts";

const { DatabaseSync } = createRequire(import.meta.url)("node:sqlite") as typeof import("node:sqlite");

/** The slice of the D1 API the adapter uses, backed by a real SQLite database. */
function sqliteD1(): D1Database {
  const sqlite = new DatabaseSync(":memory:");
  const prepare = (sql: string) => {
    let args: unknown[] = [];
    const stmt = {
      bind(...a: unknown[]) {
        args = a;
        return stmt;
      },
      async first<T>() {
        return (sqlite.prepare(sql).get(...(args as never[])) as T | undefined) ?? null;
      },
      async all<T>() {
        return { results: sqlite.prepare(sql).all(...(args as never[])) as T[] };
      },
      async run() {
        const r = sqlite.prepare(sql).run(...(args as never[]));
        return { meta: { changes: Number(r.changes) } };
      },
    };
    return stmt;
  };
  return { prepare } as unknown as D1Database;
}

describe("D1StorageAdapter against real SQLite", () => {
  let d1: D1StorageAdapter;
  beforeEach(async () => {
    d1 = await D1StorageAdapter.create(sqliteD1());
  });

  it("creates its table on first use and round-trips set/get", async () => {
    expect(await d1.get("tokens", "gmail")).toBeNull(); // table missing: created, retried
    await d1.set("tokens", "gmail", { a: 1 });
    expect(await d1.get("tokens", "gmail")).toEqual({ a: 1 });
    await d1.set("tokens", "gmail", { a: 2 }); // upsert
    expect(await d1.get("tokens", "gmail")).toEqual({ a: 2 });
    expect(await d1.get("other", "gmail")).toBeNull(); // collections are separate
  });

  it("delete removes only the named document", async () => {
    await d1.set("tokens", "a", { n: 1 });
    await d1.set("tokens", "b", { n: 2 });
    await d1.delete("tokens", "a");
    expect(await d1.get("tokens", "a")).toBeNull();
    expect(await d1.get("tokens", "b")).toEqual({ n: 2 });
  });

  it("setIfAbsent and setIfUnchanged are conditional", async () => {
    expect(await d1.setIfAbsent("tokens", "a", { n: 1 })).toBe(true);
    expect(await d1.setIfAbsent("tokens", "a", { n: 2 })).toBe(false);
    const read = (await d1.get("tokens", "a"))!;
    expect(await d1.setIfUnchanged("tokens", "a", read, { n: 3 })).toBe(true);
    expect(await d1.setIfUnchanged("tokens", "a", read, { n: 4 })).toBe(false); // stale copy
    expect(await d1.get("tokens", "a")).toEqual({ n: 3 });
  });

  it("entries and count read the right collection", async () => {
    await d1.set("audit", "1", { t: "2026-01-01T00:00:00Z" });
    await d1.set("audit", "2", { t: "2026-03-01T00:00:00Z" });
    await d1.set("tokens", "x", { t: "2026-03-01T00:00:00Z" });
    expect((await d1.entries("audit")).map(([k]) => k).sort()).toEqual(["1", "2"]);
    expect(await d1.count("audit")).toBe(2);
    expect(await d1.count("audit", { since: "2026-02-01T00:00:00Z", timestampField: "t" })).toBe(1);
  });

  it("prune deletes only older string timestamps in the collection", async () => {
    await d1.set("audit", "old", { t: "2026-01-01T00:00:00Z" });
    await d1.set("audit", "new", { t: "2026-03-01T00:00:00Z" });
    await d1.set("audit", "none", { other: 1 }); // no timestamp: kept
    await d1.set("audit", "num", { t: 5 }); // non-string timestamp: kept
    await d1.set("tokens", "old", { t: "2026-01-01T00:00:00Z" }); // other collection: kept
    expect(await d1.prune("audit", "2026-02-01T00:00:00Z", "t")).toBe(1);
    expect((await d1.entries("audit")).map(([k]) => k).sort()).toEqual(["new", "none", "num"]);
    expect(await d1.get("tokens", "old")).not.toBeNull();
  });

  it("list orders newest first and pages through one timestamp by key", async () => {
    const same = "2026-03-01T00:00:00Z";
    await d1.set("audit", "a", { timestamp: same });
    await d1.set("audit", "b", { timestamp: same });
    await d1.set("audit", "c", { timestamp: same });
    await d1.set("audit", "old", { timestamp: "2026-01-01T00:00:00Z" });
    await d1.set("audit", "new", { timestamp: "2026-04-01T00:00:00Z" });
    const keys = async (q: Parameters<D1StorageAdapter["list"]>[1]) => (await d1.list("audit", q)).map(([k]) => k);
    expect(await keys({})).toEqual(["new", "c", "b", "a", "old"]);
    expect(await keys({ limit: 2 })).toEqual(["new", "c"]);
    // A timestamp alone skips the rest of that instant; the key keeps it.
    expect(await keys({ before: same })).toEqual(["old"]);
    expect(await keys({ before: same, beforeKey: "c", limit: 2 })).toEqual(["b", "a"]);
    expect(await keys({ before: same, beforeKey: "a" })).toEqual(["old"]);
    expect(await keys({ since: same, before: "2026-04-01T00:00:00Z", beforeKey: "new" })).toEqual(["c", "b", "a"]);
  });
});
