// Time-ordered queries over a collection, shared by adapters that hold their
// documents in memory. A document's timestamp is its string `timestampField`;
// anything else counts as "" (oldest, never matches `since`, never pruned).

import type { StoredDocument, TimeQuery } from "../../runtime/context.ts";

export const DEFAULT_TIMESTAMP_FIELD = "timestamp";

const FIELD_RE = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;

/** The field name, validated: adapters splice it into SQL, so it is never free text. */
export function timestampFieldOf(q: Pick<TimeQuery, "timestampField">): string {
  const f = q.timestampField ?? DEFAULT_TIMESTAMP_FIELD;
  if (!FIELD_RE.test(f)) throw new Error("Invalid timestamp field");
  return f;
}

export function docTimestamp(doc: StoredDocument, field: string): string {
  const v = (doc as Record<string, unknown> | null)?.[field];
  return typeof v === "string" ? v : "";
}

/** Newest-first window: filter by since/before, sort by timestamp desc (key desc on ties), limit. */
export function queryByTime(
  entries: Array<[string, StoredDocument]>,
  q: TimeQuery,
): Array<[string, StoredDocument]> {
  const field = timestampFieldOf(q);
  const rows = entries
    .map((e) => ({ e, ts: docTimestamp(e[1], field) }))
    .filter(({ ts }) => (q.since === undefined || ts >= q.since) && (q.before === undefined || ts < q.before));
  rows.sort((a, b) => (a.ts === b.ts ? (a.e[0] < b.e[0] ? 1 : -1) : a.ts < b.ts ? 1 : -1));
  const out = rows.map((r) => r.e);
  return q.limit !== undefined && q.limit >= 0 ? out.slice(0, q.limit) : out;
}

export function countSince(
  entries: Array<[string, StoredDocument]>,
  q: Pick<TimeQuery, "since" | "timestampField">,
): number {
  if (q.since === undefined) return entries.length;
  const field = timestampFieldOf(q);
  let n = 0;
  for (const [, d] of entries) if (docTimestamp(d, field) >= q.since) n++;
  return n;
}

/** Keys of documents whose timestamp is a non-empty string older than `olderThan`. */
export function staleKeys(entries: Array<[string, StoredDocument]>, olderThan: string, field: string): string[] {
  const f = timestampFieldOf({ timestampField: field });
  const out: string[] = [];
  for (const [k, d] of entries) {
    const ts = docTimestamp(d, f);
    if (ts !== "" && ts < olderThan) out.push(k);
  }
  return out;
}
