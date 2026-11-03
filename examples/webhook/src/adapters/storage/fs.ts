// Node filesystem storage adapter: a single JSON file under /data holding all
// collections, written atomically (tmp + rename). Low-level on purpose — the
// list-response shaping (meta-only projection + SENSITIVE_FIELDS stripping)
// lives in the storage module so every adapter shares one audited filter.

import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import {
  ALL_COLLECTIONS,
  type StorageAdapter,
  type StoredDocument,
  type TimeQuery,
} from "../../runtime/context.ts";
import { countSince, queryByTime, staleKeys } from "./timeQuery.ts";

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

  // Single-flight flush. A mutation marks the store dirty and joins the write in
  // progress; the writer loops until nothing is dirty, so every caller's promise
  // resolves only after a write that includes its change, and at most one write
  // runs at a time (no interleaved renames, no shared temp file).
  private dirty = false;
  private flushing: Promise<void> | null = null;
  private tmpSeq = 0;

  private flush(): Promise<void> {
    this.dirty = true;
    if (!this.flushing) this.flushing = this.runFlush();
    return this.flushing;
  }

  private async runFlush(): Promise<void> {
    try {
      while (this.dirty) {
        this.dirty = false;
        const tmp = `${this.path}.${process.pid}.${++this.tmpSeq}.tmp`;
        try {
          await mkdir(dirname(this.path), { recursive: true });
          await writeFile(tmp, JSON.stringify(this.store), "utf-8");
          await rename(tmp, this.path);
        } catch (e) {
          this.dirty = true; // not persisted: the next mutation retries
          await rm(tmp, { force: true }).catch(() => {});
          throw e;
        }
      }
    } finally {
      // Same tick as the loop's last dirty check: a mutation arriving after this
      // starts a new flush instead of joining one that has already finished.
      this.flushing = null;
    }
  }

  async get(collection: string, key: string): Promise<StoredDocument | null> {
    return this.collection(collection)[key] ?? null;
  }

  async set(collection: string, key: string, data: StoredDocument): Promise<void> {
    this.collection(collection)[key] = data;
    await this.flush();
  }

  /** Atomic insert-if-absent (the check and the write share one tick). */
  async setIfAbsent(collection: string, key: string, data: StoredDocument): Promise<boolean> {
    const col = this.collection(collection);
    if (Object.hasOwn(col, key)) return false;
    col[key] = data;
    await this.flush();
    return true;
  }

  async delete(collection: string, key: string): Promise<void> {
    delete this.collection(collection)[key];
    await this.flush();
  }

  async entries(collection: string): Promise<Array<[string, StoredDocument]>> {
    return Object.entries(this.collection(collection));
  }

  async count(collection: string, opts: Pick<TimeQuery, "since" | "timestampField"> = {}): Promise<number> {
    return countSince(Object.entries(this.collection(collection)), opts);
  }

  async list(collection: string, opts: TimeQuery): Promise<Array<[string, StoredDocument]>> {
    return queryByTime(Object.entries(this.collection(collection)), opts);
  }

  async prune(collection: string, olderThan: string, timestampField: string): Promise<number> {
    const col = this.collection(collection);
    const stale = staleKeys(Object.entries(col), olderThan, timestampField);
    for (const k of stale) delete col[k];
    if (stale.length > 0) await this.flush();
    return stale.length;
  }
}
