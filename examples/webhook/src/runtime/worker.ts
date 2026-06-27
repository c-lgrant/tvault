// Cloudflare Workers entry point. Builds the RuntimeContext from bindings:
//   - secrets:  HKDF-derived in memory from the TV_WEBHOOK_SEED Secret. Nothing
//               secret is ever persisted; the key material is stable across
//               redeploys because the seed is.
//   - storage:  D1 (binding `DB`) — durable, strongly-consistent credential
//               storage. The `kv` table self-creates on first request.
//   - replay:   the per-colo Cache API (no binding, no daily write quota).
// No KV namespace: storage is D1, replay is the Cache API, and the seed is a
// Secret — so the Worker needs exactly one auto-provisioned resource (D1).
// The app is built once per isolate and reused across requests.

import type { Hono } from "hono";
import { createApp, type AppEnv } from "../core/app.ts";
import { allModules } from "../modules/index.ts";
import { configFromEnv } from "./config.ts";
import { seedDerivedSecrets } from "../adapters/secrets/seedDerived.ts";
import { D1StorageAdapter } from "../adapters/storage/d1.ts";
import { CacheReplayGuard } from "../adapters/replay/cache.ts";
import type { RuntimeContext } from "./context.ts";
import { runStartup } from "./startup.ts";

export interface Env {
  /** The one persisted secret — AES key + HMAC secret are HKDF-derived from it. */
  TV_WEBHOOK_SEED?: string;
  /** D1 database holding credentials. Auto-provisioned at deploy; required. */
  DB?: D1Database;
  /** String config vars are read by configFromEnv. */
  [key: string]: unknown;
}

let appPromise: Promise<Hono<AppEnv>> | null = null;

async function buildApp(env: Env): Promise<Hono<AppEnv>> {
  if (!env.DB) {
    throw new Error(
      "No 'DB' D1 binding — credential storage requires D1. Wrangler auto-provisions it " +
        "on deploy when database_id is omitted from wrangler.toml (see deploy/cloudflare/README.md).",
    );
  }

  const ctx: RuntimeContext = {
    config: configFromEnv((k) => (typeof env[k] === "string" ? (env[k] as string) : undefined)),
    secrets: seedDerivedSecrets(env.TV_WEBHOOK_SEED),
    storage: await D1StorageAdapter.create(env.DB),
    replay: new CacheReplayGuard(),
  };
  await runStartup(ctx); // memoized by appPromise: runs once per isolate
  return createApp(ctx, allModules());
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    // Self-healing memo: if buildApp rejects (e.g. startup storage I/O fails)
    // we clear the cached promise so the next request gets a fresh attempt
    // rather than re-awaiting the same rejected promise forever.
    appPromise ??= buildApp(env).catch((e: unknown) => {
      appPromise = null;
      throw e;
    });
    const app = await appPromise;
    return app.fetch(request, env, ctx);
  },
} satisfies ExportedHandler<Env>;
