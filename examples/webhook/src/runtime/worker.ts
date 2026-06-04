// Cloudflare Workers entry point. Builds the RuntimeContext from bindings:
//   - secrets:  seed-derived (HKDF from the TV_WEBHOOK_SEED secret)
//   - storage:  D1 if a DB binding exists, else KV (TOKENS)
//   - replay:   KV (REPLAY)
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
  /** KV namespace for credential storage (used when no D1 binding is present). */
  TOKENS?: KVNamespace;
  /** KV namespace for replay protection (request IDs + ticket nonces). */
  REPLAY?: KVNamespace;
  /** Optional D1 database — preferred over KV for durable, consistent storage. */
  DB?: D1Database;
  /** String config vars are read by configFromEnv. */
  [key: string]: unknown;
}

let appPromise: Promise<Hono<AppEnv>> | null = null;

async function buildApp(env: Env): Promise<Hono<AppEnv>> {
  let storage: StorageAdapter;
  if (env.DB) {
    storage = await D1StorageAdapter.create(env.DB);
  } else if (env.TOKENS) {
    storage = new KvStorageAdapter(env.TOKENS);
  } else {
    throw new Error("No storage binding: configure a D1 'DB' or KV 'TOKENS' binding");
  }
  if (!env.REPLAY) throw new Error("No 'REPLAY' KV binding configured");

  const ctx: RuntimeContext = {
    config: configFromEnv((k) => (typeof env[k] === "string" ? (env[k] as string) : undefined)),
    secrets: seedDerivedSecrets(env.TV_WEBHOOK_SEED),
    storage,
    replay: new KvReplayGuard(env.REPLAY),
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
