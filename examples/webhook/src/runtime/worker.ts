// Cloudflare Workers entry point. Builds the RuntimeContext from bindings:
//   - secrets:  seed-derived (HKDF from the TV_WEBHOOK_SEED secret)
//   - storage:  D1 if a DB binding exists, else the KV namespace
//   - replay:   the same KV namespace (request IDs + ticket nonces)
// One KV namespace backs BOTH storage and replay — their keys never collide
// (replay uses `rid:`/`nonce:` prefixes, storage uses `collection:key`). Using a
// single namespace also keeps the one-click deploy simple: the wizard provisions
// one namespace instead of two same-named ones that collide with each other.
// The app is built once per isolate and reused across requests.

import type { Hono } from "hono";
import { createApp, type AppEnv } from "../core/app.ts";
import { allModules } from "../modules/index.ts";
import { configFromEnv } from "./config.ts";
import { seedDerivedSecrets } from "../adapters/secrets/seedDerived.ts";
import { KvStorageAdapter } from "../adapters/storage/kv.ts";
import { D1StorageAdapter } from "../adapters/storage/d1.ts";
import { KvReplayGuard } from "../adapters/replay/kv.ts";
import type { RuntimeContext, StorageAdapter } from "./context.ts";

export interface Env {
  /** The one persisted secret — AES key + HMAC secret are HKDF-derived from it. */
  TV_WEBHOOK_SEED?: string;
  /**
   * KV namespace backing replay protection (always) and credential storage
   * (when no D1 binding is present). Required.
   */
  KV?: KVNamespace;
  /** Optional D1 database — preferred over KV for durable credential storage. */
  DB?: D1Database;
  /** String config vars are read by configFromEnv. */
  [key: string]: unknown;
}

let appPromise: Promise<Hono<AppEnv>> | null = null;

async function buildApp(env: Env): Promise<Hono<AppEnv>> {
  if (!env.KV) {
    throw new Error(
      "No 'KV' namespace bound — required for replay protection (and for storage unless a D1 'DB' is bound)",
    );
  }

  const storage: StorageAdapter = env.DB
    ? await D1StorageAdapter.create(env.DB)
    : new KvStorageAdapter(env.KV);

  const ctx: RuntimeContext = {
    config: configFromEnv((k) => (typeof env[k] === "string" ? (env[k] as string) : undefined)),
    secrets: seedDerivedSecrets(env.TV_WEBHOOK_SEED),
    storage,
    replay: new KvReplayGuard(env.KV),
  };
  return createApp(ctx, allModules());
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    appPromise ??= buildApp(env);
    const app = await appPromise;
    return app.fetch(request, env, ctx);
  },
} satisfies ExportedHandler<Env>;
