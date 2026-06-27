// HKDF-SHA256 key derivation via WebCrypto. Used by the Worker's seed-derived
// secret provider: a single TV_WEBHOOK_SEED secret deterministically yields the
// AES key, HMAC secret, and webhook ID — stable across redeploys, never
// persisted, never seen by Token Vault.

import { type Bytes, utf8 } from "./encoding.ts";

const EMPTY_SALT = new Uint8Array(0);

/**
 * Derive `length` bytes from `seed` for a given `info` label. Distinct labels
 * produce independent key material from the same seed (RFC 5869).
 */
export async function hkdfDerive(seed: Bytes, info: string, length: number): Promise<Bytes> {
  const key = await crypto.subtle.importKey("raw", seed, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: EMPTY_SALT, info: utf8(info) },
    key,
    length * 8,
  );
  return new Uint8Array(bits);
}
