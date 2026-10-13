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
    if (q.startsWith("CREATE TABLE")) return { success: true };
    if (q.startsWith("INSERT INTO kv")) {
      this.rows.set(id, doc);
      return { success: true };
    }
    if (q.startsWith("DELETE FROM kv")) {
      this.rows.delete(id);
      return { success: true };
    }
    if (q.startsWith("SELECT doc FROM kv")) {
      const d = this.rows.get(id);
      return d === undefined ? null : { doc: d };
    }
    const inCollection = [...this.rows.entries()].filter(([k]) => k.startsWith(`${collection}\u0000`));
    if (q.startsWith("SELECT COUNT(*)")) return { n: inCollection.length };
    if (q.startsWith("SELECT k, doc FROM kv")) {
      const results = inCollection.map(([k, d]) => ({ k: k.split("\u0000")[1], doc: d }));
      return mode === "all" ? { results } : (results[0] ?? null);
    }
    throw new Error(`FakeD1: unsupported SQL: ${q}`);
  }
}
