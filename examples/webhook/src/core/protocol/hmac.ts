// HMAC-SHA256 request signing/verification via WebCrypto.
//
// Request signature (client.py:58-72): the signing message is
//   utf8(`${timestamp}.`) ‖ rawBodyBytes
// i.e. exactly TV's `f"{timestamp}.{body}"` where body is the raw received
// bytes. We concatenate at the byte level rather than decode→re-encode so the
// signature is computed over the literal bytes TV signed, never a re-serialized
// copy.

import { type Bytes, bytesToHex, constantTimeEqual, utf8 } from "../crypto/encoding.ts";

async function importKey(secret: Bytes): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    secret,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

/** Low-level: hex HMAC-SHA256 of an arbitrary message. Used by request + ticket auth. */
export async function hmacSha256Hex(secret: Bytes, message: Bytes): Promise<string> {
  const key = await importKey(secret);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
  return bytesToHex(sig);
}

function concat(a: Bytes, b: Bytes): Bytes {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

export async function computeRequestSignature(
  secret: Bytes,
  timestamp: string,
  rawBody: Bytes,
): Promise<string> {
  return hmacSha256Hex(secret, concat(utf8(`${timestamp}.`), rawBody));
}

export async function verifyRequestSignature(
  secret: Bytes,
  timestamp: string,
  rawBody: Bytes,
  providedHex: string,
): Promise<boolean> {
  const expected = await computeRequestSignature(secret, timestamp, rawBody);
  return constantTimeEqual(expected, providedHex);
}
