// Workers KV storage adapter. One namespace holds every collection, keyed
// `${collection}:${key}`. Low-level on purpose — list-response shaping lives in
// the storage module so the sensitive-field filter is shared with every adapter.
//
// Note: KV is eventually consistent and `list`+`get` fans out one read per key,
// so this fits the example's small credential set, not high-cardinality data.
// For durable, transactional storage use the D1 adapter instead.

import type { StorageAdapter, StoredDocument } from "../../runtime/context.ts";

function compositeKey(collection: string, key: string): string {
  return `${collection}:${key}`;
}

export class KvStorageAdapter implements StorageAdapter {
  constructor(private readonly kv: KVNamespace) {}

  async get(collection: string, key: string): Promise<StoredDocument | null> {
    return this.kv.get<StoredDocument>(compositeKey(collection, key), "json");
  }

  async set(collection: string, key: string, data: StoredDocument): Promise<void> {
    await this.kv.put(compositeKey(collection, key), JSON.stringify(data));
  }

  async delete(collection: string, key: string): Promise<void> {
    await this.kv.delete(compositeKey(collection, key));
  }

  async entries(collection: string): Promise<Array<[string, StoredDocument]>> {
    const prefix = `${collection}:`;
    const keys: string[] = [];
    let cursor: string | undefined;
    do {
      const page = await this.kv.list(cursor ? { prefix, cursor } : { prefix });
      for (const k of page.keys) keys.push(k.name);
      cursor = page.list_complete ? undefined : page.cursor;
    } while (cursor);

    const out = await Promise.all(
      keys.map(async (composite): Promise<[string, StoredDocument] | null> => {
        const doc = await this.kv.get<StoredDocument>(composite, "json");
        return doc ? [composite.slice(prefix.length), doc] : null;
      }),
    );
    return out.filter((e): e is [string, StoredDocument] => e !== null);
  }
}
