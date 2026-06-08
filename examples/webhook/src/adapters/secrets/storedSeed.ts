// Cloudflare Worker secret provider with an optional runtime-provisioned seed.
//
// Resolution order:
//   1. `TV_WEBHOOK_SEED` (a Workers Secret) — the HARDENED path. Write-only,
//      encrypted at rest, never readable from the store. If set, it WINS and is
//      never overwritten.
//   2. A seed stored in KV under `seed:v1` — the CONVENIENCE path. Written once
//      by the operator clicking "Generate & save" on the /bind page, so a fresh
//      deploy can self-provision with no CLI step.
//
// Either way the AES key + HMAC secret + webhook id are HKDF-derived from the
// seed in memory (see deriveSecrets) and the control plane only ever learns the
// HMAC secret via the one-time /v1/exchange handshake.
//
// SECURITY TRADEOFF (convenience path): the seed is the root key. Stored in KV
// it is readable by anyone who can read the KV namespace (account owner /
// compromised worker). We split blast radius by keeping the seed in KV and the
// CREDENTIALS in D1 — a leak of EITHER store alone decrypts nothing; you need
// both. For maximum at-rest protection set `TV_WEBHOOK_SEED` as a Secret instead.

import { type Derived, deriveSecrets } from "./seedDerived.ts";
import { bytesToHex } from "../../core/crypto/encoding.ts";
import { setupRequired } from "../../core/protocol/errors.ts";
import type { SecretProvider } from "../../runtime/context.ts";

// KV key for the convenience-path seed. Distinct prefix from replay (`rid:`/
// `nonce:`) and from any storage `collection:key`; never listed by the token API.
const SEED_KV_KEY = "seed:v1";

/** The slice of KVNamespace the seed provider needs (so tests can fake it). */
export interface SeedKvLike {
  get(key: string): Promise<string | null>;
  put(key: string, value: string): Promise<void>;
}

class StoredSeedSecretProvider implements SecretProvider {
  private seed: string | undefined;
  private seedLoaded: boolean;
  private readonly fromSecret: boolean;
  private derivedP: Promise<Derived> | null = null;

  constructor(
    envSeed: string | undefined,
    private readonly kv: SeedKvLike,
  ) {
    this.seed = envSeed || undefined;
    this.fromSecret = Boolean(this.seed);
    // With an env Secret present we never consult KV; otherwise KV is the source.
    this.seedLoaded = this.fromSecret;
  }

  /** Resolve the active seed (env Secret takes precedence; else KV). Cached. */
  private async loadSeed(): Promise<string | undefined> {
    if (this.seedLoaded) return this.seed;
    const stored = await this.kv.get(SEED_KV_KEY);
    this.seed = stored || undefined;
    this.seedLoaded = true;
    return this.seed;
  }

  private async derive(): Promise<Derived> {
    const seed = await this.loadSeed();
    if (!seed) throw setupRequired();
    this.derivedP ??= deriveSecrets(seed);
    return this.derivedP;
  }

  async isConfigured(): Promise<boolean> {
    return Boolean(await this.loadSeed());
  }

  async source(): Promise<"secret" | "stored" | "none"> {
    if (this.fromSecret) return "secret";
    return (await this.loadSeed()) ? "stored" : "none";
  }

  /**
   * Generate a 32-byte seed and persist it to KV — but only if none exists.
   * A Workers Secret or an already-stored seed is never overwritten (rotating
   * the seed would change the HMAC secret and break an existing Token Vault
   * bind). Returns whether a new seed was created.
   */
  async provision(): Promise<{ created: boolean }> {
    if (this.fromSecret) return { created: false };
    if (await this.loadSeed()) return { created: false };
    const seed = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
    await this.kv.put(SEED_KV_KEY, seed);
    this.seed = seed;
    this.seedLoaded = true;
    this.derivedP = null; // re-derive from the freshly minted seed
    return { created: true };
  }

  async hmacSecret() {
    return (await this.derive()).hmacSecret;
  }
  async encryptionKey() {
    return (await this.derive()).encryptionKey;
  }
  async webhookId() {
    return (await this.derive()).webhookId;
  }
  async hmacSecretHash() {
    return (await this.derive()).hmacSecretHash;
  }
}

/**
 * Seed provider that prefers a `TV_WEBHOOK_SEED` Secret and otherwise uses (or
 * provisions) a seed stored in KV. See the file header for the security tradeoff.
 */
export function storedSeedSecrets(opts: {
  envSeed?: string | undefined;
  kv: SeedKvLike;
}): SecretProvider {
  return new StoredSeedSecretProvider(opts.envSeed, opts.kv);
}
