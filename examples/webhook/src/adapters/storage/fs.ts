// Node filesystem storage adapter: a single JSON file under /data holding all
// collections, written atomically (tmp + rename). Low-level on purpose — the
// list-response shaping (meta-only projection + SENSITIVE_FIELDS stripping)
// lives in the storage module so every adapter shares one audited filter.

import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import {
  ALL_COLLECTIONS,
  type StorageAdapter,
  type StoredDocument,
} from "../../runtime/context.ts";

type Store = Record<string, Record<string, StoredDocument>>;

const DEFAULT_PATH = "/data/tokenvault_kv_store.json";

export class FsStorageAdapter implements StorageAdapter {
  private constructor(
    private readonly path: string,
    private readonly store: Store,
  ) {}

  static async create(path?: string): Promise<FsStorageAdapter> {
    const resolved = path ?? process.env.TOKENVAULT_KV_STORE_PATH ?? DEFAULT_PATH;
    const store: Store = {};
    for (const c of ALL_COLLECTIONS) store[c] = {};

    try {
      const data = JSON.parse(await readFile(resolved, "utf-8")) as Record<string, unknown>;
      for (const c of ALL_COLLECTIONS) {
        const loaded = data[c];
        if (loaded && typeof loaded === "object") {
          store[c] = loaded as Record<string, StoredDocument>;
        }
      }
    } catch {
      // Missing or unreadable file — start fresh.
    }

    return new FsStorageAdapter(resolved, store);
  }

  private collection(name: string): Record<string, StoredDocument> {
    const col = this.store[name];
    if (!col) throw new Error(`Unknown collection: ${name}`);
    return col;
  }

  private async flush(): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true });
    const tmp = `${this.path}.tmp`;
    await writeFile(tmp, JSON.stringify(this.store), "utf-8");
    await rename(tmp, this.path);
  }

  async get(collection: string, key: string): Promise<StoredDocument | null> {
    return this.collection(collection)[key] ?? null;
  }

  async set(collection: string, key: string, data: StoredDocument): Promise<void> {
    this.collection(collection)[key] = data;
    await this.flush();
  }

  async delete(collection: string, key: string): Promise<void> {
    delete this.collection(collection)[key];
    await this.flush();
  }

  async entries(collection: string): Promise<Array<[string, StoredDocument]>> {
    return Object.entries(this.collection(collection));
  }
}
