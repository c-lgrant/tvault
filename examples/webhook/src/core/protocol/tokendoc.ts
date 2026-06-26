// Encrypted token-document helpers (crypto.py:64-112). Shared by the store,
// credential, proxy, refresh and refresh-notify modules so the on-disk format
// and the hasX capability flags stay consistent across every write path.

import { decrypt, encrypt } from "../crypto/aesgcm.ts";
import type { Bytes } from "../crypto/encoding.ts";
import type { StoredDocument } from "../../runtime/context.ts";

/** Sensitive fields beyond access/refresh tokens that are encrypted, not stored as meta. */
export const EXTRA_SENSITIVE_FIELDS = [
  "certificateData",
  "privateKeyData",
  "certificateChain",
  "sshPrivateKey",
  "totpSecret",
] as const;

export async function buildEncryptedTokenDocument(
  key: Bytes,
  accessToken: string | null,
  refreshToken: string | null,
  meta: Record<string, unknown>,
  extraSensitive?: Record<string, unknown>,
): Promise<StoredDocument> {
  const fields: Record<string, string> = {};
  if (accessToken != null) fields.accessToken = await encrypt(key, accessToken);
  if (refreshToken != null) fields.refreshToken = await encrypt(key, refreshToken);

  if (extraSensitive) {
    for (const [name, value] of Object.entries(extraSensitive)) {
      if (value != null) fields[name] = await encrypt(key, String(value));
    }
  }

  if (!("hasRefreshToken" in meta)) {
    meta.hasRefreshToken = refreshToken != null && String(refreshToken).length > 0;
  }
  meta.hasCertificate = "certificateData" in fields;
  meta.hasPrivateKey = "privateKeyData" in fields;
  meta.hasSSHKey = "sshPrivateKey" in fields;
  meta.hasTotpSecret = "totpSecret" in fields;

  return { v: 1, alg: "AES-256-GCM", fields, meta };
}

/** Decrypt one field from an encrypted document's `fields` map; null if absent. */
export async function decryptTokenField(
  key: Bytes,
  doc: StoredDocument,
  field: string,
): Promise<string | null> {
  const fields = (doc.fields ?? {}) as Record<string, string>;
  const encrypted = fields[field];
  if (!encrypted) return null;
  return decrypt(key, encrypted);
}

/**
 * Flatten a stored document into a plaintext token object. Handles both
 * storage formats: encrypted (`{v,alg,fields,meta}` — decrypt fields, merge
 * meta) and plaintext (written by the TV backend via /v1/storage `set` — strip
 * the internal `id`).
 */
export async function readTokenObject(
  key: Bytes,
  doc: StoredDocument,
): Promise<Record<string, unknown>> {
  if ("fields" in doc) {
    const fields = (doc.fields ?? {}) as Record<string, string>;
    const meta = (doc.meta ?? {}) as Record<string, unknown>;
    const token: Record<string, unknown> = {};
    for (const [name, value] of Object.entries(fields)) {
      if (value) token[name] = await decrypt(key, value);
    }
    for (const [name, value] of Object.entries(meta)) {
      if (!(name in token)) token[name] = value;
    }
    return token;
  }

  const token: Record<string, unknown> = {};
  for (const [name, value] of Object.entries(doc)) {
    if (name !== "id") token[name] = value;
  }
  return token;
}
