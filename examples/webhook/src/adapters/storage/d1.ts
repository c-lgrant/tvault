// Workers D1 storage adapter — durable, strongly-consistent credential storage.
// A single table keys documents by (collection, k); the JSON document is
// stored verbatim. Preferred over KV when refresh writes and reads must be
// transactional. The table is created lazily: every query is tried first and
// the schema is created (idempotently) only if D1 reports it missing, so a
// cold start on an existing database pays no extra round trip.

import type { StorageAdapter, StoredDocument, TimeQuery } from "../../runtime/context.ts";
import { timestampFieldOf } from "./timeQuery.ts";

interface Row {
  doc: string;
}
interface EntryRow {
  k: string;
  doc: string;
}

/** The document's timestamp as text; "" when absent or not a string (matches the in-memory adapters). */
function tsExpr(field: string): string {
  return `CASE WHEN json_type(doc, '$.${field}') = 'text' THEN json_extract(doc, '$.${field}') ELSE '' END`;
}

export class D1StorageAdapter implements StorageAdapter {
  private schemaReady = false;

  private constructor(private readonly db: D1Database) {}

  static async create(db: D1Database): Promise<D1StorageAdapter> {
    return new D1StorageAdapter(db);
  }

  private async ensureSchema(): Promise<void> {
    await this.db
      .prepare(
        `CREATE TABLE IF NOT EXISTS kv (
           collection TEXT NOT NULL,
           k TEXT NOT NULL,
           doc TEXT NOT NULL,
           PRIMARY KEY (collection, k)
         )`,
      )
      .run();
    this.schemaReady = true;
  }

  /** Run a query; if the table does not exist yet, create it and retry once. */
  private async q<T>(run: () => Promise<T>): Promise<T> {
    try {
      return await run();
    } catch (e) {
      if (this.schemaReady || !/no such table/i.test(e instanceof Error ? e.message : String(e))) throw e;
      await this.ensureSchema();
      return run();
    }
  }

  async get(collection: string, key: string): Promise<StoredDocument | null> {
    const row = await this.q(() =>
      this.db.prepare("SELECT doc FROM kv WHERE collection = ? AND k = ?").bind(collection, key).first<Row>(),
    );
    return row ? this.parse(row.doc) : null;
  }

  // The exact stored text of each document handed out, so a conditional write can
  // compare against what is in the database byte for byte (a re-serialised copy
  // might not match).
  private readonly sourceText = new WeakMap<object, string>();

  private parse(text: string): StoredDocument {
    const doc = JSON.parse(text) as StoredDocument;
    this.sourceText.set(doc, text);
    return doc;
  }

  /** Replace the document only if its stored text is still the one `expected` was read from. */
  async setIfUnchanged(
    collection: string,
    key: string,
    expected: StoredDocument,
    data: StoredDocument,
  ): Promise<boolean> {
    const was = this.sourceText.get(expected) ?? JSON.stringify(expected);
    const res = await this.q(() =>
      this.db
        .prepare("UPDATE kv SET doc = ? WHERE collection = ? AND k = ? AND doc = ?")
        .bind(JSON.stringify(data), collection, key, was)
        .run(),
    );
    return (res.meta?.changes ?? 0) > 0;
  }

  async set(collection: string, key: string, data: StoredDocument): Promise<void> {
    await this.q(() =>
      this.db
        .prepare(
          `INSERT INTO kv (collection, k, doc) VALUES (?, ?, ?)
           ON CONFLICT(collection, k) DO UPDATE SET doc = excluded.doc`,
        )
        .bind(collection, key, JSON.stringify(data))
        .run(),
    );
  }

  /** Atomic insert-if-absent. Returns false (and writes nothing) when the key exists. */
  async setIfAbsent(collection: string, key: string, data: StoredDocument): Promise<boolean> {
    const res = await this.q(() =>
      this.db
        .prepare("INSERT INTO kv (collection, k, doc) VALUES (?, ?, ?) ON CONFLICT(collection, k) DO NOTHING")
        .bind(collection, key, JSON.stringify(data))
        .run(),
    );
    return (res.meta?.changes ?? 0) > 0;
  }

  async delete(collection: string, key: string): Promise<void> {
    await this.q(() => this.db.prepare("DELETE FROM kv WHERE collection = ? AND k = ?").bind(collection, key).run());
  }

  async entries(collection: string): Promise<Array<[string, StoredDocument]>> {
    const result = await this.q(() =>
      this.db.prepare("SELECT k, doc FROM kv WHERE collection = ?").bind(collection).all<EntryRow>(),
    );
    return (result.results ?? []).map((r) => [r.k, JSON.parse(r.doc) as StoredDocument]);
  }

  async count(collection: string, opts: Pick<TimeQuery, "since" | "timestampField"> = {}): Promise<number> {
    let sql = "SELECT COUNT(*) AS n FROM kv WHERE collection = ?";
    const args: unknown[] = [collection];
    if (opts.since !== undefined) {
      sql += ` AND ${tsExpr(timestampFieldOf(opts))} >= ?`;
      args.push(opts.since);
    }
    const row = await this.q(() =>
      this.db.prepare(sql).bind(...args).first<{ n: number }>(),
    );
    return row?.n ?? 0;
  }

  /** Newest-first window, ordered and limited in SQL so only `limit` rows leave the database. */
  async list(collection: string, opts: TimeQuery): Promise<Array<[string, StoredDocument]>> {
    const ts = tsExpr(timestampFieldOf(opts));
    let sql = "SELECT k, doc FROM kv WHERE collection = ?";
    const args: unknown[] = [collection];
    if (opts.since !== undefined) {
      sql += ` AND ${ts} >= ?`;
      args.push(opts.since);
    }
    if (opts.before !== undefined) {
      sql += ` AND ${ts} < ?`;
      args.push(opts.before);
    }
    sql += ` ORDER BY ${ts} DESC, k DESC`;
    if (opts.limit !== undefined && opts.limit >= 0) {
      sql += " LIMIT ?";
      args.push(Math.floor(opts.limit));
    }
    const result = await this.q(() => this.db.prepare(sql).bind(...args).all<EntryRow>());
    return (result.results ?? []).map((r) => [r.k, JSON.parse(r.doc) as StoredDocument]);
  }

  /** Delete documents whose string timestamp is older than `olderThan`. */
  async prune(collection: string, olderThan: string, timestampField: string): Promise<number> {
    const ts = tsExpr(timestampFieldOf({ timestampField }));
    const res = await this.q(() =>
      this.db
        .prepare(`DELETE FROM kv WHERE collection = ? AND ${ts} <> '' AND ${ts} < ?`)
        .bind(collection, olderThan)
        .run(),
    );
    return res.meta?.changes ?? 0;
  }
}
