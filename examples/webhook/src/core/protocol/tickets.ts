// Credential-ticket verification (credential_tickets.py + auth.py:109-162).
//
// Ticket format:  `${base64url(compact_json)}.${hex_hmac}`
// The signature is HMAC-SHA256 over the base64url payload STRING (not the
// decoded bytes). Verification recomputes over that same string, constant-time
// compares, then re-pads + decodes the payload, checks expiry, and guards the
// nonce against replay.

import {
  base64UrlDecode,
  base64UrlEncodeNoPad,
  type Bytes,
  constantTimeEqual,
  fromUtf8,
  utf8,
} from "../crypto/encoding.ts";
import { hmacSha256Hex } from "./hmac.ts";
import { ticketExpired, ticketInvalid } from "./errors.ts";
import type { TicketPayload } from "./types.ts";
import type { ReplayGuard } from "../../runtime/context.ts";

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

/**
 * Sign a ticket. The webhook only ever *verifies* TV-issued tickets in
 * production; this exists for tests and to keep the sign/verify pair colocated.
 * `JSON.stringify` emits compact JSON (no spaces), matching TV's
 * `separators=(",",":")`.
 */
export async function signTicket(secret: Bytes, payload: TicketPayload): Promise<string> {
  const payloadB64 = base64UrlEncodeNoPad(utf8(JSON.stringify(payload)));
  const sig = await hmacSha256Hex(secret, utf8(payloadB64));
  return `${payloadB64}.${sig}`;
}

/**
 * Verify a ticket's signature, expiry, and nonce. Throws a WebhookError on any
 * failure; returns the decoded payload on success.
 */
export async function verifyTicket(
  ticket: string,
  secret: Bytes,
  replay: ReplayGuard,
): Promise<TicketPayload> {
  const parts = ticket.split(".");
  if (parts.length !== 2) throw ticketInvalid("Malformed ticket");
  const payloadB64 = parts[0]!;
  const providedSig = parts[1]!;

  const expected = await hmacSha256Hex(secret, utf8(payloadB64));
  if (!constantTimeEqual(expected, providedSig)) {
    throw ticketInvalid("HMAC signature verification failed");
  }

  let payload: TicketPayload;
  try {
    payload = JSON.parse(fromUtf8(base64UrlDecode(payloadB64))) as TicketPayload;
  } catch {
    throw ticketInvalid("Failed to decode ticket payload");
  }

  if ((payload.exp ?? 0) < nowSeconds()) {
    throw ticketExpired("Ticket has expired");
  }

  const nonce = payload.nonce ?? "";
  if (nonce && (await replay.checkNonce(nonce))) {
    throw ticketInvalid("Ticket nonce already used (replay)");
  }

  return payload;
}
