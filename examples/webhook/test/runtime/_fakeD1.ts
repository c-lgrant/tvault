// In-memory stand-in for the D1 binding, covering only the SQL the D1 storage
// adapter issues. `hold()` makes the next query hang until released — the
// shape of a cold-start build whose request was cancelled mid-I/O.

type Row = Record<string, unknown>;

export class FakeD1 {
  readonly rows = new Map<string, string>(); // `${collection}\u0000${k}` -> doc
  readonly log: string[] = [];
  private held: Array<() => void> = [];
  private holdNext = 0;
  private failNext = 0;
  /** Model a missing table: queries throw "no such table" until CREATE TABLE runs. */
  tableExists = false;
  requireSchema = true;

  /** The next `n` queries never settle until `release()` is called. */
  hold(n = 1): void {
    this.holdNext += n;
  }

  /** The next `n` queries reject. */
  fail(n = 1): void {
    this.failNext += n;
  }

  release(): void {
    for (const r of this.held.splice(0)) r();
  }

  prepare(sql: string) {
    const db = this;
    let args: unknown[] = [];
    const stmt = {
      bind(...a: unknown[]) {
        args = a;
        return stmt;
      },
      first: <T = Row>() => db.exec(sql, args, "first") as Promise<T | null>,
      all: <T = Row>() => db.exec(sql, args, "all") as Promise<{ results: T[] }>,
      run: () => db.exec(sql, args, "run"),
    };
    return stmt;
  }

  private async exec(sql: string, args: unknown[], mode: "first" | "all" | "run"): Promise<unknown> {
    const q = sql.replace(/\s+/g, " ").trim();
    this.log.push(q);
    if (this.failNext > 0) {
      this.failNext--;
      throw new Error("D1_ERROR: simulated failure");
    }
    if (this.holdNext > 0) {
      this.holdNext--;
      await new Promise<void>((resolve) => this.held.push(resolve));
    }
    const [collection, key, doc] = args as string[];
    const id = `${collection}\u0000${key}`;
    if (q.startsWith("CREATE TABLE")) {
      this.tableExists = true;
      return { success: true };
    }
    if (this.requireSchema && !this.tableExists) throw new Error("D1_ERROR: no such table: kv: SQLITE_ERROR");
    // Timestamp field named in a json_extract(doc, '$.<field>') expression.
    const field = /\$\.(\w+)/.exec(q)?.[1] ?? "timestamp";
    const tsOf = (d: string): string => {
      const v = (JSON.parse(d) as Record<string, unknown>)[field];
      return typeof v === "string" ? v : "";
    };
    if (q.startsWith("UPDATE kv SET doc")) {
      const [next, col, k, was] = args as string[];
      const rid = `${col}\u0000${k}`;
      if (this.rows.get(rid) !== was) return { success: true, meta: { changes: 0 } };
      this.rows.set(rid, next!);
      return { success: true, meta: { changes: 1 } };
    }
    if (q.startsWith("INSERT INTO kv")) {
      if (q.includes("DO NOTHING")) {
        if (this.rows.has(id)) return { success: true, meta: { changes: 0 } };
        this.rows.set(id, doc);
        return { success: true, meta: { changes: 1 } };
      }
      this.rows.set(id, doc);
      return { success: true, meta: { changes: 1 } };
    }
    if (q.startsWith("DELETE FROM kv") && q.includes("json_type")) {
      const [col, olderThan] = args as string[];
      let changes = 0;
      for (const [rk, d] of [...this.rows.entries()]) {
        const ts = tsOf(d);
        if (rk.startsWith(`${col}\u0000`) && ts !== "" && ts < olderThan!) {
          this.rows.delete(rk);
          changes++;
        }
      }
      return { success: true, meta: { changes } };
    }
    if (q.startsWith("DELETE FROM kv")) {
      this.rows.delete(id);
      return { success: true, meta: { changes: 1 } };
    }
    if (q.includes("ORDER BY")) {
      // list(): args = collection, [since], [before], [limit]
      const rest = args.slice(1) as string[];
      let i = 0;
      const since = q.includes(">= ?") ? rest[i++] : undefined;
      const before = q.includes("< ? ORDER") ? rest[i++] : undefined;
      const limit = q.includes("LIMIT ?") ? Number(rest[i++]) : undefined;
      this.log.push("LIST");
      const rows = [...this.rows.entries()]
        .filter(([rk]) => rk.startsWith(`${collection}\u0000`))
        .map(([rk, d]) => ({ k: rk.split("\u0000")[1]!, doc: d, ts: tsOf(d) }))
        .filter((r) => (since === undefined || r.ts >= since) && (before === undefined || r.ts < before))
        .sort((a, b) => (a.ts === b.ts ? (a.k < b.k ? 1 : -1) : a.ts < b.ts ? 1 : -1));
      const results = (limit === undefined ? rows : rows.slice(0, limit)).map(({ k, doc }) => ({ k, doc }));
      return { results };
    }
    if (q.startsWith("SELECT doc FROM kv")) {
      const d = this.rows.get(id);
      return d === undefined ? null : { doc: d };
    }
    const inCollection = [...this.rows.entries()].filter(([k]) => k.startsWith(`${collection}\u0000`));
    if (q.startsWith("SELECT COUNT(*)")) {
      const since = q.includes(">= ?") ? (args[1] as string) : undefined;
      return { n: inCollection.filter(([, d]) => since === undefined || tsOf(d) >= since).length };
    }
    if (q.startsWith("SELECT k, doc FROM kv")) {
      const results = inCollection.map(([k, d]) => ({ k: k.split("\u0000")[1], doc: d }));
      return mode === "all" ? { results } : (results[0] ?? null);
    }
    throw new Error(`FakeD1: unsupported SQL: ${q}`);
  }
}
