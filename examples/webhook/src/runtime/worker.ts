// Cloudflare Workers entry point. Builds the RuntimeContext from bindings:
//   - secrets:  HKDF-derived in memory from the TV_WEBHOOK_SEED Secret. Nothing
//               secret is ever persisted; the key material is stable across
//               redeploys because the seed is.
//   - storage:  D1 (binding `DB`) — durable, strongly-consistent credential
//               storage. The `kv` table self-creates on first request.
//   - replay:   ticket nonces in D1 (atomic insert, pruned by the cron);
//               request ids in the per-colo Cache API (no binding).
// No KV namespace: storage and nonces are D1, request ids are the Cache API,
// and the seed is a Secret — so the Worker needs exactly one auto-provisioned
// resource (D1).
// The app is built once per isolate and reused across requests.
//
// Only the FINISHED app is shared. On Workers, I/O belongs to the request that
// started it: if that request is cancelled mid-build (client timeout), the
// build's D1 calls are cancelled and its promise never settles. Sharing an
// in-flight build promise would make every later request on the isolate await
// it forever. So a request that finds no app yet runs its own build (startup is
// idempotent) and the first build to finish is kept.

import type { Hono } from "hono";
import { createApp, type AppEnv } from "../core/app.ts";
import { allModules } from "../modules/index.ts";
import { configFromEnv } from "./config.ts";
import { seedDerivedSecrets } from "../adapters/secrets/seedDerived.ts";
import { D1StorageAdapter } from "../adapters/storage/d1.ts";
import { CacheReplayGuard } from "../adapters/replay/cache.ts";
import { pruneNonces, StoredNonceGuard } from "../adapters/replay/stored.ts";
import type { RuntimeContext } from "./context.ts";
import { runStartup } from "./startup.ts";
import { refreshDueTokens } from "../core/protocol/oauthRefresh.ts";
import { pruneAudit } from "../core/protocol/retention.ts";

export interface Env {
  /** The one persisted secret — AES key + HMAC secret are HKDF-derived from it. */
  TV_WEBHOOK_SEED?: string;
  /** D1 database holding credentials. Auto-provisioned at deploy; required. */
  DB?: D1Database;
  /** String config vars are read by configFromEnv. */
  [key: string]: unknown;
}

let builtApp: Hono<AppEnv> | null = null;
let builtCtx: RuntimeContext | null = null;

async function buildContext(env: Env): Promise<RuntimeContext> {
  if (!env.DB) {
    throw new Error(
      "No 'DB' D1 binding — credential storage requires D1. Wrangler auto-provisions it " +
        "on deploy when database_id is omitted from wrangler.toml (see deploy/cloudflare/README.md).",
    );
  }

  const storage = await D1StorageAdapter.create(env.DB);
  const cache = new CacheReplayGuard();
  const ctx: RuntimeContext = {
    config: configFromEnv((k) => (typeof env[k] === "string" ? (env[k] as string) : undefined)),
    secrets: seedDerivedSecrets(env.TV_WEBHOOK_SEED),
    storage,
    // Ticket nonces go to D1 (one atomic insert each) unless the operator chose
    // the best-effort cache with TV_REPLAY_NONCES=cache.
    replay: env.TV_REPLAY_NONCES === "cache" ? cache : new StoredNonceGuard(storage, cache),
  };
  await runStartup(ctx); // once per isolate, unless concurrent cold requests race
  return ctx;
}

async function buildApp(env: Env): Promise<Hono<AppEnv>> {
  const ctx = builtCtx ?? (builtCtx = await buildContext(env));
  return createApp(ctx, allModules({ tvRefreshEnabled: ctx.config.tvRefreshEnabled === true }));
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    // A failed build caches nothing, so the next request simply tries again.
    const app = builtApp ?? (builtApp = await buildApp(env));
    return app.fetch(request, env, ctx);
  },

  // Cron trigger (wrangler.toml [triggers]): refresh own-app OAuth tokens
  // before they expire. Token Vault never asks for this; the webhook owns it.
  async scheduled(_controller: ScheduledController, env: Env): Promise<void> {
    const ctx = builtCtx ?? (builtCtx = await buildContext(env));
    try {
      await refreshDueTokens(ctx);
    } finally {
      // Audit retention rides the same cron; a failed refresh sweep must not skip it.
      await pruneAudit(ctx).catch(() => console.error("[retention] audit prune failed"));
      await pruneNonces(ctx.rawStorage ?? ctx.storage).catch(() => console.error("[replay] nonce prune failed"));
    }
  },
} satisfies ExportedHandler<Env>;
