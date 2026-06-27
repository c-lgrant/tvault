// AES-256-GCM via WebCrypto (crypto.subtle), shared by Node and Workers.
//
// Wire format: base64( 12-byte IV ‖ ciphertext ‖ 16-byte tag ), no AAD.
// WebCrypto's encrypt() returns ciphertext‖tag concatenated, which matches the
// Python reference's `iv + AESGCM(key).encrypt(iv, pt, None)` exactly.

import { base64Decode, base64Encode, type Bytes, fromUtf8, utf8 } from "./encoding.ts";

const IV_LENGTH = 12;
const MIN_RAW_LENGTH = IV_LENGTH + 16; // IV + GCM tag, no ciphertext

async function importKey(key: Bytes): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", key, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

export async function encrypt(key: Bytes, plaintext: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const cryptoKey = await importKey(key);
  const ctWithTag = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, cryptoKey, utf8(plaintext)),
  );
  const out = new Uint8Array(iv.length + ctWithTag.length);
  out.set(iv, 0);
  out.set(ctWithTag, iv.length);
  return base64Encode(out);
}

export async function decrypt(key: Bytes, ciphertextB64: string): Promise<string> {
  if (!ciphertextB64) throw new Error("Ciphertext is empty");

  let raw: Uint8Array;
  try {
    raw = base64Decode(ciphertextB64);
  } catch (e) {
    throw new Error(`Invalid base64 ciphertext: ${(e as Error).message}`);
  }

  if (raw.length < MIN_RAW_LENGTH) {
    throw new Error(
      `Ciphertext too short (${raw.length} bytes, need at least ${MIN_RAW_LENGTH})`,
    );
  }

  const iv = raw.slice(0, IV_LENGTH);
  const ctWithTag = raw.slice(IV_LENGTH);
  const cryptoKey = await importKey(key);

  let ptBytes: ArrayBuffer;
  try {
    ptBytes = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, cryptoKey, ctWithTag);
  } catch (e) {
    throw new Error(
      `AES-GCM decryption failed (wrong key or corrupted ciphertext): ${(e as Error).message}`,
    );
  }

  return fromUtf8(new Uint8Array(ptBytes));
}
