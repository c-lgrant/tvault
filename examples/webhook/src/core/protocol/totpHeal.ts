// Heal-on-read for legacy tokens that stored an otpauth:// URI (seed included)
// as plaintext meta. Wraps the storage adapter so every read path
// (/v1/credential, /v1/totp-code, /v1/proxy, /v1/storage get/list) migrates the
// document: seed -> encrypted `totpSecret`, descriptors -> meta, `totpUri` gone.
// The URI is never returned or logged, even if a document cannot be migrated.

import type { RuntimeContext, StorageAdapter, StoredDocument } from "../../runtime/context.ts";
import { encrypt } from "../crypto/aesgcm.ts";
import { parseTotpUri, totpDescriptors } from "./totpUri.ts";

function metaOf(doc: StoredDocument): Record<string, unknown> | null {
  const m = (doc as Record<string, unknown>).meta;
  return m && typeof m === "object" ? (m as Record<string, unknown>) : null;
}

/** True when an encrypted-format doc still carries a URI in meta. */
function needsHeal(doc: StoredDocument): boolean {
  if (!doc || typeof doc !== "object" || !("fields" in doc)) return false;
  const meta = metaOf(doc);
  return meta != null && "totpUri" in meta;
}

/** Copy of the doc with `meta.totpUri` removed (used when migration is impossible). */
function redacted(doc: StoredDocument): StoredDocument {
  const { totpUri: _drop, ...meta } = metaOf(doc) ?? {};
  return { ...doc, meta };
}

/**
 * Migrate one document. Returns the healed doc and whether it was rewritten.
 * Documents that don't need healing are returned as-is.
 */
export async function healDoc(
  ctx: Pick<RuntimeContext, "secrets">,
  raw: StorageAdapter,
  collection: string,
  key: string,
  doc: StoredDocument,
): Promise<{ doc: StoredDocument; rewritten: boolean }> {
  if (collection !== "tokens" || !needsHeal(doc)) return { doc, rewritten: false };
  const meta = { ...(metaOf(doc) ?? {}) };
  const fields = { ...((doc.fields ?? {}) as Record<string, string>) };
  const uri = meta.totpUri;
  delete meta.totpUri;
  try {
    if (!fields.totpSecret) {
      if (typeof uri !== "string") return { doc: redacted(doc), rewritten: false };
      const parsed = parseTotpUri(uri);
      if (!(await ctx.secrets.isConfigured())) return { doc: redacted(doc), rewritten: false };
      fields.totpSecret = await encrypt(await ctx.secrets.encryptionKey(), parsed.secret);
      Object.assign(meta, totpDescriptors(parsed));
      meta.hasTotpSecret = true;
      if (!meta.tokenType) meta.tokenType = "TOTP";
    }
    const healed: StoredDocument = { ...doc, fields, meta };
    await raw.set(collection, key, healed);
    return { doc: healed, rewritten: true };
  } catch {
    // Unparseable URI or storage failure: serve without the URI, leave stored doc.
    return { doc: redacted(doc), rewritten: false };
  }
}

/** Storage adapter that heals legacy totpUri documents on get/entries. */
export function healingStorage(ctx: Pick<RuntimeContext, "secrets">, raw: StorageAdapter): StorageAdapter {
  return {
    async get(collection, key) {
      const doc = await raw.get(collection, key);
      return doc ? (await healDoc(ctx, raw, collection, key, doc)).doc : doc;
    },
    set: (collection, key, data) => raw.set(collection, key, data),
    delete: (collection, key) => raw.delete(collection, key),
    async entries(collection) {
      const all = await raw.entries(collection);
      if (collection !== "tokens") return all;
      return Promise.all(
        all.map(async ([k, d]): Promise<[string, StoredDocument]> => [
          k,
          (await healDoc(ctx, raw, collection, k, d)).doc,
        ]),
      );
    },
  };
}

/** Sweep every stored token; returns counts only (never values). */
export async function migrateAllTotp(
  ctx: Pick<RuntimeContext, "secrets">,
  raw: StorageAdapter,
): Promise<{ scanned: number; migrated: number; failed: number }> {
  const entries = await raw.entries("tokens");
  let migrated = 0;
  let failed = 0;
  for (const [key, doc] of entries) {
    if (!needsHeal(doc)) continue;
    const { rewritten } = await healDoc(ctx, raw, "tokens", key, doc);
    if (rewritten) migrated++;
    else failed++;
  }
  return { scanned: entries.length, migrated, failed };
}
