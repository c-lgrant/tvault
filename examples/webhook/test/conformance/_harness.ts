// In-memory RuntimeContext for tests — no disk, no network. Not a *.test.ts, so
// vitest does not execute it directly.

import {
  type RuntimeContext,
  type SecretProvider,
  type StorageAdapter,
  type StoredDocument,
  type WebhookConfig,
} from "../../src/runtime/context.ts";
import { type Bytes, bytesToHex } from "../../src/core/crypto/encoding.ts";
import { MemoryReplayGuard } from "../../src/adapters/replay/memory.ts";

class MemoryStorage implements StorageAdapter {
  private readonly store = new Map<string, Map<string, StoredDocument>>();

  private col(name: string): Map<string, StoredDocument> {
    let c = this.store.get(name);
    if (!c) {
      c = new Map();
      this.store.set(name, c);
    }
    return c;
  }

  async get(collection: string, key: string): Promise<StoredDocument | null> {
    return this.col(collection).get(key) ?? null;
  }
  async set(collection: string, key: string, data: StoredDocument): Promise<void> {
    this.col(collection).set(key, data);
  }
  async delete(collection: string, key: string): Promise<void> {
    this.col(collection).delete(key);
  }
  async entries(collection: string): Promise<Array<[string, StoredDocument]>> {
    return [...this.col(collection).entries()];
  }
}

class StaticSecret implements SecretProvider {
  constructor(
    private readonly hmac: Bytes,
    private readonly key: Bytes,
  ) {}
  async isConfigured(): Promise<boolean> {
    return true;
  }
  async hmacSecret(): Promise<Bytes> {
    return this.hmac;
  }
  async encryptionKey(): Promise<Bytes> {
    return this.key;
  }
  async webhookId(): Promise<string> {
    return "wh_test";
  }
  async hmacSecretHash(): Promise<string> {
    return bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", this.hmac)));
  }
}

export function makeContext(opts: {
  hmacSecret: Bytes;
  encryptionKey?: Bytes;
  denyIps?: string[];
  denyOrigins?: string[];
}): RuntimeContext {
  const key = opts.encryptionKey ?? crypto.getRandomValues(new Uint8Array(32));
  const config: WebhookConfig = {
    version: "2.0.0",
    timestampTolerance: 300,
    tokenvaultFrontendUrl: "https://tokenvault.test",
    denyIps: opts.denyIps ?? [],
    denyOrigins: opts.denyOrigins ?? [],
  };
  return {
    config,
    secrets: new StaticSecret(opts.hmacSecret, key),
    storage: new MemoryStorage(),
    replay: new MemoryReplayGuard(),
  };
}
