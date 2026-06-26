// Wire-level protocol constants and types. These mirror the Token Vault
// control-plane contract byte-for-byte; see backend/webhook/client.py,
// credential_tickets.py and the webhook routes for the authoritative source.

/** Protocol version advertised at /v1/exchange and /v1/health. */
export const WEBHOOK_VERSION = "2.0.0";

/** Max clock skew (seconds) tolerated on X-TokenVault-Timestamp. */
export const TIMESTAMP_TOLERANCE = 300;

/** Standard signed-request headers TV sends. */
export const HEADER_SIGNATURE = "X-TokenVault-Signature";
export const HEADER_TIMESTAMP = "X-TokenVault-Timestamp";
export const HEADER_REQUEST_ID = "X-TokenVault-Request-Id";

/**
 * Sensitive credential fields that must never appear in a list response, and
 * which the store/refresh paths encrypt rather than store as plaintext meta.
 */
export const SENSITIVE_FIELDS: ReadonlySet<string> = new Set([
  "accessToken",
  "refreshToken",
  "certificateData",
  "privateKeyData",
  "certificateChain",
  "sshPrivateKey",
  "totpSecret",
]);

/** Decoded credential-ticket payload (credential_tickets.py). */
export interface TicketPayload {
  /** Vault owner user ID. */
  sub: string;
  /** Service name. */
  svc: string;
  /** Purpose — one of the values TV issues. */
  pur: string;
  iat: number;
  exp: number;
  nonce: string;
  /** Optional agent ID (audit). */
  aid?: string;
  /** Optional proxy config ID (audit). */
  pid?: string;
}

/**
 * Encrypted token document on disk/KV.
 *   { v: 1, alg: "AES-256-GCM", fields: { accessToken: <b64>, ... }, meta: {...} }
 * Tokens written by the TV backend via /v1/storage `set` are plaintext objects
 * instead (no `fields`); both shapes are read on retrieval.
 */
export interface EncryptedTokenDocument {
  v: number;
  alg: string;
  fields: Record<string, string>;
  meta: Record<string, unknown>;
}
