// Runtime context: the per-runtime bundle of adapters + config that the
// runtime-neutral core and feature modules are built against. `node.ts` and
// `worker.ts` each construct one of these from their own adapters and hand it
// to `createApp()`.

import type { Bytes } from "../core/crypto/encoding.ts";

/** Fixed set of storage collections the TV control plane reads/writes. */
export const KNOWN_COLLECTIONS = [
  "tokens",
  "proxy_configs",
  "audit",
  "vault_config",
] as const;

export type Collection = (typeof KNOWN_COLLECTIONS)[number];

/** A stored document is an opaque JSON object keyed by string. */
export type StoredDocument = Record<string, unknown>;

/** Static configuration, identical shape across runtimes. */
export interface WebhookConfig {
  /** Protocol version advertised at /v1/exchange and /v1/health. */
  version: string;
  /** Max clock skew (seconds) tolerated on request timestamps. */
  timestampTolerance: number;
  /** Token Vault frontend origin, used to build the bind/register URL. */
  tokenvaultFrontendUrl: string;
  /** This webhook's own public URL (for the register-URL flow). */
  externalUrl?: string;
  /**
   * Client IPs that must be rejected on the credential + store endpoints.
   * Token Vault's own server egress IP belongs here: a real ticket replayed
   * from TV's IP must NOT yield a credential (TV stays zero-knowledge).
   */
  denyIps: string[];
  /** Origins rejected on the credential + store endpoints. */
  denyOrigins: string[];
  /**
   * OAuth client credentials the webhook owns, keyed by lower-cased provider
   * name (e.g. "github", "google"). The refresh-notify path reads the
   * `clientSecret` from HERE and NEVER from the request's refresh hint — the
   * Python reference's bug (refresh.py:246 trusts the hint) is fixed by this.
   */
  oauthProviders?: Record<string, OAuthProviderConfig>;
}

/** Locally-provisioned OAuth client credentials for autonomous refresh. */
export interface OAuthProviderConfig {
  /** OAuth client secret — sourced locally, never from the TV-supplied hint. */
  clientSecret: string;
  /** Client ID; falls back to the refresh hint when omitted. */
  clientId?: string;
  /** Token endpoint; falls back to the refresh hint when omitted. */
  tokenUrl?: string;
}

/**
 * Owns the webhook's key material. The control plane never sees any of it.
 *
 * - `fileSecret` (Node): generates + persists keys to disk on first run.
 * - `seedDerived` (Worker): HKDF-derives keys in memory from `TV_WEBHOOK_SEED`,
 *   stable across redeploys, never persisted.
 */
export interface SecretProvider {
  /** True once key material exists (always true for seed-derived). */
  isConfigured(): Promise<boolean>;
  /** Shared HMAC secret (raw bytes) used for request + ticket signatures. */
  hmacSecret(): Promise<Bytes>;
  /** AES-256 key (raw bytes) used to encrypt credentials at rest. */
  encryptionKey(): Promise<Bytes>;
  /** Stable opaque webhook identifier. */
  webhookId(): Promise<string>;
  /** Hex SHA-256 of the HMAC secret — published in the register URL, verified by TV. */
  hmacSecretHash(): Promise<string>;
}

export interface ListOptions {
  limit?: number;
  after?: string;
  since?: string;
  filters?: Record<string, unknown>;
}

/**
 * Low-level key-value storage, swapped per runtime (fs / KV / D1). It is
 * deliberately dumb: list-response *shaping* (meta-only projection, sensitive
 * field stripping, audit handling, pagination) lives in the storage module so
 * the security-critical filter cannot diverge between adapters.
 */
export interface StorageAdapter {
  get(collection: string, key: string): Promise<StoredDocument | null>;
  set(collection: string, key: string, data: StoredDocument): Promise<void>;
  delete(collection: string, key: string): Promise<void>;
  /** All [key, document] pairs in a collection (unshaped). */
  entries(collection: string): Promise<Array<[string, StoredDocument]>>;
}

/**
 * Replay protection for request IDs and ticket nonces. Each call records the
 * value and reports whether it had already been seen (within its TTL window).
 */
export interface ReplayGuard {
  /** TTL ~10 min. Returns true if this request ID was already used. */
  checkRequestId(id: string): Promise<boolean>;
  /** TTL ~2 min. Returns true if this ticket nonce was already used. */
  checkNonce(nonce: string): Promise<boolean>;
}

/** Everything a module needs at request time. */
export interface RuntimeContext {
  config: WebhookConfig;
  secrets: SecretProvider;
  storage: StorageAdapter;
  replay: ReplayGuard;
}
