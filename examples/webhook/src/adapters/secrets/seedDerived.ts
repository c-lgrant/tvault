// Cloudflare Worker secret provider — the locked key-custody model.
//
// A single `wrangler secret put TV_WEBHOOK_SEED` is the ONLY persisted secret.
// The AES-256 key, the HMAC secret, and the webhook ID are all HKDF-derived
// from it in memory (distinct info labels → independent material), never written
// to KV/D1, and stable across redeploys because the seed is stable. Token Vault
// only ever learns the HMAC secret, and only through the one-time /v1/exchange
// handshake — never the encryption key.

import { hkdfDerive } from "../../core/crypto/hkdf.ts";
import { type Bytes, bytesToHex, utf8 } from "../../core/crypto/encoding.ts";
import { setupRequired } from "../../core/protocol/errors.ts";
import type { SecretProvider } from "../../runtime/context.ts";

// Versioned info labels — bumping a label rotates that derived value.
const INFO_ENCRYPTION_KEY = "tv-webhook:encryption-key:v1";
const INFO_HMAC_SECRET = "tv-webhook:hmac-secret:v1";
const INFO_WEBHOOK_ID = "tv-webhook:webhook-id:v1";

interface Derived {
  encryptionKey: Bytes;
  hmacSecret: Bytes;
  webhookId: string;
  hmacSecretHash: string;
}

async function sha256Hex(b: Bytes): Promise<string> {
  return bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", b)));
}

class SeedDerivedSecretProvider implements SecretProvider {
  private derived: Promise<Derived> | null = null;

  constructor(private readonly seed: string | undefined) {}

  private deriveAll(): Promise<Derived> {
    if (!this.seed) throw setupRequired();
    const seedBytes = utf8(this.seed);
    this.derived ??= (async () => {
      const [encryptionKey, hmacSecret, idBytes] = await Promise.all([
        hkdfDerive(seedBytes, INFO_ENCRYPTION_KEY, 32),
        hkdfDerive(seedBytes, INFO_HMAC_SECRET, 32),
        hkdfDerive(seedBytes, INFO_WEBHOOK_ID, 16),
      ]);
      return {
        encryptionKey,
        hmacSecret,
        webhookId: `wh_${bytesToHex(idBytes)}`,
        hmacSecretHash: await sha256Hex(hmacSecret),
      };
    })();
    return this.derived;
  }

  async isConfigured(): Promise<boolean> {
    return Boolean(this.seed);
  }
  async hmacSecret(): Promise<Bytes> {
    return (await this.deriveAll()).hmacSecret;
  }
  async encryptionKey(): Promise<Bytes> {
    return (await this.deriveAll()).encryptionKey;
  }
  async webhookId(): Promise<string> {
    return (await this.deriveAll()).webhookId;
  }
  async hmacSecretHash(): Promise<string> {
    return (await this.deriveAll()).hmacSecretHash;
  }
}

/** Build a seed-derived secret provider; an absent seed reports unconfigured. */
export function seedDerivedSecrets(seed: string | undefined): SecretProvider {
  return new SeedDerivedSecretProvider(seed);
}
