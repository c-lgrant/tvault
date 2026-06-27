// Workers D1 storage adapter — durable, strongly-consistent credential storage.
// A single table keys documents by (collection, key); the JSON document is
// stored verbatim. Preferred over KV when refresh writes and reads must be
// transactional. Call `ensureSchema()` once (it is idempotent) before serving.

import type { StorageAdapter, StoredDocument } from "../../runtime/context.ts";

interface Row {
  doc: string;
}
interface EntryRow {
  k: string;
  doc: string;
}

export class D1StorageAdapter implements StorageAdapter {
  private constructor(private readonly db: D1Database) {}

  static async create(db: D1Database): Promise<D1StorageAdapter> {
    const adapter = new D1StorageAdapter(db);
    await adapter.ensureSchema();
    return adapter;
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
  }

  async get(collection: string, key: string): Promise<StoredDocument | null> {
    const row = await this.db
      .prepare("SELECT doc FROM kv WHERE collection = ? AND k = ?")
      .bind(collection, key)
      .first<Row>();
    return row ? (JSON.parse(row.doc) as StoredDocument) : null;
  }

  async set(collection: string, key: string, data: StoredDocument): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO kv (collection, k, doc) VALUES (?, ?, ?)
         ON CONFLICT(collection, k) DO UPDATE SET doc = excluded.doc`,
      )
      .bind(collection, key, JSON.stringify(data))
      .run();
  }

  async delete(collection: string, key: string): Promise<void> {
    await this.db.prepare("DELETE FROM kv WHERE collection = ? AND k = ?").bind(collection, key).run();
  }

  async entries(collection: string): Promise<Array<[string, StoredDocument]>> {
    const result = await this.db
      .prepare("SELECT k, doc FROM kv WHERE collection = ?")
      .bind(collection)
      .all<EntryRow>();
    return (result.results ?? []).map((r) => [r.k, JSON.parse(r.doc) as StoredDocument]);
  }
}
