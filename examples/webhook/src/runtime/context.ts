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

/**
 * Internal collections the webhook persists for its own bookkeeping (e.g. the
 * durable bind-state flag). These are deliberately NOT part of
 * `KNOWN_COLLECTIONS`, so the agent-facing `/v1/storage` endpoint — which gates
 * on `isKnownCollection` — never exposes them. Storage adapters must still
 * initialize them so internal reads/writes work on every runtime.
 */
export const INTERNAL_COLLECTIONS = ["meta"] as const;

/** Every collection an adapter must provision: agent-facing plus internal. */
export const ALL_COLLECTIONS = [
  ...KNOWN_COLLECTIONS,
  ...INTERNAL_COLLECTIONS,
] as const;

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
   * Admin secret that gates re-binding after the first successful exchange.
   * Set via TV_ADMIN_SECRET. When absent, a bound webhook is fully sealed —
   * no re-bind is possible until the secret is configured.
   */
  adminSecret?: string;
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
  /**
   * Where the active key material comes from, for the bind-page security UX:
   * `secret` (hardened, write-only Secret), `stored` (convenience, seed in a
   * runtime-writable store), or `none` (not configured yet). Optional.
   */
  source?(): Promise<"secret" | "stored" | "none">;
  /**
   * Generate + persist key material if none exists, for one-click setup. Returns
   * whether it created any (false if already configured — existing material is
   * never overwritten, since rotating it would break an existing bind). Optional:
   * providers that require out-of-band provisioning (e.g. a Workers Secret) omit
   * it, and callers must feature-detect before offering a "generate" action.
   */
  provision?(): Promise<{ created: boolean }>;
}

export interface ListOptions {
  limit?: number;
  after?: string;
  since?: string;
  filters?: Record<string, unknown>;
}

/**
 * Low-level key-value storage, swapped per runtime (fs on Node / D1 on Workers). It is
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
