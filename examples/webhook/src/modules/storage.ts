// KV storage endpoint for the TV backend (metadata.py:48-83 + store.py
// kv_execute). HMAC-authenticated. The list path is the security-critical one:
// it projects each stored document down to non-sensitive *meta* only, so
// SENSITIVE_FIELDS (and encrypted `fields` blobs) never appear in a list.

import { hmacAuth } from "../core/middleware/hmacAuth.ts";
import { invalidRequest } from "../core/protocol/errors.ts";
import { SENSITIVE_FIELDS } from "../core/protocol/types.ts";
import { readJsonBody } from "../core/middleware/body.ts";
import { sendError } from "../core/middleware/respond.ts";
import {
  KNOWN_COLLECTIONS,
  type ListOptions,
  type StorageAdapter,
  type StoredDocument,
} from "../runtime/context.ts";
import type { FeatureModule } from "../core/registry.ts";
import { isBefore } from "../adapters/storage/timeQuery.ts";

const DOC_INTERNAL_KEYS = new Set(["v", "alg", "fields", "meta"]);

interface ListItem {
  key: string;
  meta: Record<string, unknown>;
  data?: unknown;
}

interface Pagination {
  hasMore: boolean;
  nextCursor: string | null;
  totalCount: number;
}

function isKnownCollection(name: unknown): name is string {
  return typeof name === "string" && (KNOWN_COLLECTIONS as readonly string[]).includes(name);
}

function auditTimestamp(item: ListItem): string {
  const data = item.data;
  if (data && typeof data === "object" && "timestamp" in data) {
    const ts = (data as Record<string, unknown>).timestamp;
    return typeof ts === "string" ? ts : "";
  }
  return "";
}

// Audit cursor: "<timestamp>|<key>". Several events can share one timestamp, so
// the key breaks the tie; a timestamp alone would skip the rest of that instant
// on the next page. A cursor without "|" is a plain timestamp (spec < 2.11.0).
const CURSOR_SEP = "|";

function auditCursor(item: ListItem): string {
  return `${auditTimestamp(item)}${CURSOR_SEP}${item.key}`;
}

function parseAuditCursor(after: string): { before: string; beforeKey?: string } {
  const i = after.indexOf(CURSOR_SEP);
  return i < 0 ? { before: after } : { before: after.slice(0, i), beforeKey: after.slice(i + 1) };
}

/** Newest first; on the same timestamp, the higher key first (the stores' order). */
function compareAudit(a: ListItem, b: ListItem): number {
  const ta = auditTimestamp(a);
  const tb = auditTimestamp(b);
  if (ta !== tb) return ta < tb ? 1 : -1;
  return a.key === b.key ? 0 : a.key < b.key ? 1 : -1;
}

/** Project a collection's raw entries into list items, stripping sensitive data. */
function shapeItems(collection: string, entries: Array<[string, StoredDocument]>): ListItem[] {
  return entries.map(([key, v]) => {
    const meta: Record<string, unknown> = {};
    if (v && typeof v === "object") {
      const storedMeta = (v as Record<string, unknown>).meta;
      if (storedMeta && typeof storedMeta === "object") {
        Object.assign(meta, storedMeta as Record<string, unknown>);
      }
      if (!("serviceName" in meta)) meta.serviceName = key;
      // Plaintext docs keep metadata at the top level — surface all of it
      // except sensitive credentials and the encrypted-doc internals.
      for (const [mk, mv] of Object.entries(v)) {
        if (!(mk in meta) && !SENSITIVE_FIELDS.has(mk) && !DOC_INTERNAL_KEYS.has(mk)) {
          meta[mk] = mv;
        }
      }
      if (!("hasRefreshToken" in meta) && "refreshToken" in v) {
        meta.hasRefreshToken = Boolean((v as Record<string, unknown>).refreshToken);
      }
    } else {
      meta.serviceName = key;
    }

    const item: ListItem = { key, meta };
    if (collection === "audit") item.data = v;
    return item;
  });
}

/**
 * List a collection. A paginated audit list (a `limit` and no `filters`) is
 * ordered, bounded and counted by the store, so only a page of rows leaves it;
 * everything else loads the collection and shapes it in memory.
 */
async function listCollection(
  storage: StorageAdapter,
  collection: string,
  options: ListOptions | undefined,
): Promise<{ items: ListItem[]; pagination?: Pagination }> {
  if (options) {
    for (const name of ["after", "since"] as const) {
      const v: unknown = options[name];
      if (v !== undefined && typeof v !== "string") throw invalidRequest(`'options.${name}' must be a string`);
    }
  }
  const limit = options?.limit;
  const hasFilters =
    options?.filters && typeof options.filters === "object" && Object.keys(options.filters).length > 0;
  if (
    collection === "audit" &&
    storage.list &&
    options &&
    typeof limit === "number" &&
    Number.isFinite(limit) &&
    limit > 0 &&
    !hasFilters &&
    (options.since === undefined || typeof options.since === "string") &&
    (options.after === undefined || typeof options.after === "string")
  ) {
    const sinceQ = options.since ? { since: options.since } : {};
    const [rows, total] = await Promise.all([
      // One extra row tells us whether another page exists.
      storage.list(collection, {
        limit: Math.floor(limit) + 1,
        ...sinceQ,
        ...(options.after ? parseAuditCursor(options.after) : {}),
      }),
      storage.count(collection, sinceQ),
    ]);
    return listResponse(collection, rows, options, total);
  }
  return listResponse(collection, await storage.entries(collection), options);
}

function listResponse(
  collection: string,
  entries: Array<[string, StoredDocument]>,
  options: ListOptions | undefined,
  totalOverride?: number,
): { items: ListItem[]; pagination?: Pagination } {
  let items = shapeItems(collection, entries);

  if (collection === "audit") {
    items.sort(compareAudit);
  }

  let pagination: Pagination | undefined;

  if (options) {
    const key = (item: ListItem) => (collection === "audit" ? auditTimestamp(item) : item.key);

    if (options.filters && typeof options.filters === "object") {
      const filters = Object.entries(options.filters);
      items = items.filter((item) => {
        const src =
          collection === "audit" && item.data && typeof item.data === "object"
            ? (item.data as Record<string, unknown>)
            : item.meta;
        return filters.every(([fk, fv]) => src[fk] === fv);
      });
    }

    if (options.since) {
      const since = options.since;
      items = items.filter((item) => key(item) >= since);
    }

    const totalCount = totalOverride ?? items.length;

    if (options.after) {
      const after = options.after;
      if (collection === "audit") {
        const { before, beforeKey } = parseAuditCursor(after);
        items = items.filter((item) => isBefore(auditTimestamp(item), item.key, before, beforeKey));
      } else {
        items = items.filter((item) => key(item) > after);
      }
    }

    if (typeof options.limit === "number" && options.limit > 0) {
      const hasMore = items.length > options.limit;
      items = items.slice(0, options.limit);
      const last = items[items.length - 1];
      const nextCursor = hasMore && last ? (collection === "audit" ? auditCursor(last) : key(last)) : null;
      pagination = { hasMore, nextCursor, totalCount };
    }
  }

  return pagination ? { items, pagination } : { items };
}

async function execute(
  storage: StorageAdapter,
  operation: string,
  collection: unknown,
  key: unknown,
  data: unknown,
  options: ListOptions | undefined,
  collections: unknown,
): Promise<Record<string, unknown>> {
  if (operation === "list_batch") {
    if (!Array.isArray(collections)) {
      throw invalidRequest("'collections' required for list_batch");
    }
    const results: Record<string, unknown> = {};
    for (const col of collections) {
      if (!isKnownCollection(col)) continue;
      results[col] = await listCollection(storage, col, options);
    }
    return { results };
  }

  if (!isKnownCollection(collection)) {
    throw invalidRequest(`Unknown collection: ${String(collection)}`);
  }

  switch (operation) {
    case "get": {
      if (typeof key !== "string" || !key) throw invalidRequest("'key' required for get");
      return { data: await storage.get(collection, key) };
    }
    case "list":
      return listCollection(storage, collection, options);
    case "set": {
      if (typeof key !== "string" || !key) throw invalidRequest("'key' required for set");
      if (!data || typeof data !== "object") throw invalidRequest("'data' required for set");
      await storage.set(collection, key, data as StoredDocument);
      return { status: "ok" };
    }
    case "delete": {
      if (typeof key !== "string" || !key) throw invalidRequest("'key' required for delete");
      await storage.delete(collection, key);
      return { status: "ok" };
    }
    default:
      throw invalidRequest(`Unknown operation: ${operation}`);
  }
}

export function storageModule(): FeatureModule {
  return {
    name: "storage",
    capability: "storage",
    register(app, ctx) {
      app.post("/v1/storage", hmacAuth(ctx), async (c) => {
        const body = readJsonBody(c);
        const operation = body.operation;
        if (typeof operation !== "string" || !operation) {
          return sendError(c, invalidRequest("Missing 'operation'"));
        }
        const requestId =
          (typeof body.requestId === "string" && body.requestId) ||
          c.req.header("X-TokenVault-Request-Id") ||
          undefined;
        try {
          const result = await execute(
            ctx.storage,
            operation,
            body.collection,
            body.key,
            body.data,
            body.options as ListOptions | undefined,
            body.collections,
          );
          return c.json({ ...result, requestId });
        } catch (e) {
          return sendError(c, e);
        }
      });
    },
  };
}
