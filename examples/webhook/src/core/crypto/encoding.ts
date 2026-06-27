// Encoding helpers shared by the protocol + crypto layers. Pure, no I/O.
// btoa/atob and TextEncoder/TextDecoder exist in both Node 18+ and Workers.

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/**
 * Bytes guaranteed to be backed by a plain ArrayBuffer (not SharedArrayBuffer).
 * WebCrypto's `BufferSource` excludes the shared variant, so the byte values we
 * feed `crypto.subtle` must use this narrower type rather than bare Uint8Array.
 */
export type Bytes = Uint8Array<ArrayBuffer>;

export function utf8(s: string): Bytes {
  return new Uint8Array(encoder.encode(s));
}

export function fromUtf8(b: Uint8Array): string {
  return decoder.decode(b);
}

export function bytesToHex(b: Uint8Array): string {
  let out = "";
  for (const byte of b) out += byte.toString(16).padStart(2, "0");
  return out;
}

export function hexToBytes(hex: string): Bytes {
  if (hex.length % 2 !== 0) throw new Error("invalid hex length");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function binaryString(b: Uint8Array): string {
  let s = "";
  for (const byte of b) s += String.fromCharCode(byte);
  return s;
}

export function base64Encode(b: Uint8Array): string {
  return btoa(binaryString(b));
}

export function base64Decode(s: string): Bytes {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** base64url without padding — matches Python `urlsafe_b64encode(...).rstrip("=")`. */
export function base64UrlEncodeNoPad(b: Uint8Array): string {
  return base64Encode(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Decode base64url, restoring the stripped padding (`+ "=" * (-len % 4)`). */
export function base64UrlDecode(s: string): Bytes {
  const padded = s + "=".repeat((4 - (s.length % 4)) % 4);
  return base64Decode(padded.replace(/-/g, "+").replace(/_/g, "/"));
}

/**
 * Constant-time string comparison over UTF-8 bytes. Mirrors Python's
 * `hmac.compare_digest`: length differences short-circuit (length is not
 * secret here — both sides are fixed-width hex digests), content does not.
 */
export function constantTimeEqual(a: string, b: string): boolean {
  const ab = utf8(a);
  const bb = utf8(b);
  if (ab.length !== bb.length) return false;
  let diff = 0;
  for (let i = 0; i < ab.length; i++) diff |= ab[i]! ^ bb[i]!;
  return diff === 0;
}

/**
 * SHA-256 of a UTF-8 string, hex-encoded (64 chars). Use this to compare two
 * arbitrary-length secrets in constant time: hash both sides first, then
 * constantTimeEqual the digests. Because every digest is the same length, the
 * length-mismatch short-circuit in constantTimeEqual never fires, so the
 * comparison can't leak the secret's length through timing.
 */
export async function sha256Hex(s: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", utf8(s));
  return bytesToHex(new Uint8Array(digest));
}
