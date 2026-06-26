// Node file-backed secret provider. On first run it generates a random AES-256
// key + HMAC secret + webhook ID and persists them atomically to /data; on
// subsequent runs it loads them. Token Vault never sees any of this material.

import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import {
  base64Decode,
  base64Encode,
  type Bytes,
  bytesToHex,
} from "../../core/crypto/encoding.ts";
import type { SecretProvider } from "../../runtime/context.ts";

interface Persisted {
  webhook_id: string;
  encryption_key: string; // base64
  hmac_secret: string; // base64
  hmac_secret_hash: string; // hex sha256(hmac_secret)
}

const DEFAULT_PATH = "/data/tokenvault_store.json";

async function sha256Hex(b: Bytes): Promise<string> {
  return bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", b)));
}

export class FileSecretProvider implements SecretProvider {
  private constructor(
    private readonly path: string,
    private readonly data: Persisted,
    private readonly keyBytes: Bytes,
    private readonly hmacBytes: Bytes,
  ) {}

  static async create(path?: string): Promise<FileSecretProvider> {
    const resolved = path ?? process.env.TOKENVAULT_STORE_PATH ?? DEFAULT_PATH;
    try {
      const data = JSON.parse(await readFile(resolved, "utf-8")) as Persisted;
      if (data.encryption_key && data.hmac_secret) {
        const keyBytes = base64Decode(data.encryption_key);
        const hmacBytes = base64Decode(data.hmac_secret);
        if (!data.hmac_secret_hash) data.hmac_secret_hash = await sha256Hex(hmacBytes);
        return new FileSecretProvider(resolved, data, keyBytes, hmacBytes);
      }
    } catch {
      // Missing or invalid store — provision fresh keys.
    }
    return FileSecretProvider.provision(resolved);
  }

  private static async provision(path: string): Promise<FileSecretProvider> {
    const keyBytes = crypto.getRandomValues(new Uint8Array(32));
    const hmacBytes = crypto.getRandomValues(new Uint8Array(32));
    const data: Persisted = {
      webhook_id: crypto.randomUUID(),
      encryption_key: base64Encode(keyBytes),
      hmac_secret: base64Encode(hmacBytes),
      hmac_secret_hash: await sha256Hex(hmacBytes),
    };
    const provider = new FileSecretProvider(path, data, keyBytes, hmacBytes);
    await provider.persist();
    return provider;
  }

  private async persist(): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true });
    const tmp = `${this.path}.tmp`;
    await writeFile(tmp, JSON.stringify(this.data), "utf-8");
    await rename(tmp, this.path);
  }

  async isConfigured(): Promise<boolean> {
    return true;
  }
  async hmacSecret(): Promise<Bytes> {
    return this.hmacBytes;
  }
  async encryptionKey(): Promise<Bytes> {
    return this.keyBytes;
  }
  async webhookId(): Promise<string> {
    return this.data.webhook_id;
  }
  async hmacSecretHash(): Promise<string> {
    return this.data.hmac_secret_hash;
  }
}
