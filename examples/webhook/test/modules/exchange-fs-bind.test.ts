// Integration tests against the REAL filesystem adapters (FsStorageAdapter +
// FileSecretProvider), not the in-memory test harness. The in-memory store
// auto-creates any collection on access, which masked a bug where the bind-code
// collection (`_bind_codes`) was never registered in INTERNAL_COLLECTIONS — so
// the Node runtime's FS adapter (which only provisions ALL_COLLECTIONS and
// rejects the rest) returned 500 "Unknown collection: _bind_codes" on every
// bind. These tests exercise the bind/seal flow and the in-place-upgrade
// guarantees (identity + data preserved across redeploy, safe boot migration)
// on the adapter that actually ships in the container runtime.

import { describe, it, expect } from "vitest";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mkdtemp, rm } from "node:fs/promises";
import { createApp } from "../../src/core/app.ts";
import { allModules } from "../../src/modules/index.ts";
import { FsStorageAdapter } from "../../src/adapters/storage/fs.ts";
import { FileSecretProvider } from "../../src/adapters/secrets/fileSecret.ts";
import { MemoryReplayGuard } from "../../src/adapters/replay/memory.ts";
import { runStartup } from "../../src/runtime/startup.ts";
import { applyPendingMigrations, CURRENT_SCHEMA_VERSION } from "../../src/migrations/index.ts";
import { isBound, markBound } from "../../src/modules/bindState.ts";
import { TIMESTAMP_TOLERANCE, WEBHOOK_VERSION } from "../../src/core/protocol/types.ts";
import type { RuntimeContext, WebhookConfig } from "../../src/runtime/context.ts";

function cfg(adminSecret?: string): WebhookConfig {
  return {
    version: WEBHOOK_VERSION,
    timestampTolerance: TIMESTAMP_TOLERANCE,
    tokenvaultFrontendUrl: "https://tokenvault.test",
    externalUrl: "https://wh.test",
    denyIps: [],
    denyOrigins: [],
    ...(adminSecret ? { adminSecret } : {}),
  };
}

// Build a context backed by the file adapters under `dir` — a brand-new pair of
// adapters reading the same files models a redeploy of the same deployment.
async function fsCtx(dir: string, adminSecret?: string): Promise<RuntimeContext> {
  const storage = await FsStorageAdapter.create(join(dir, "kv.json"));
  const secrets = await FileSecretProvider.create(join(dir, "secret.json"));
  return { config: cfg(adminSecret), secrets, storage, replay: new MemoryReplayGuard() };
}

describe("FS adapter — bind/seal flow (regression: _bind_codes must be provisioned)", () => {
  it("binds, seals on exchange, then gates re-bind on the admin secret", async () => {
    const dir = await mkdtemp(join(tmpdir(), "wh-fsbind-"));
    try {
      const ctx = await fsCtx(dir, "admin-xyz");
      const app = createApp(ctx, allModules());

      // register-url on an unbound webhook issues a one-time code (this is the
      // call that 500'd before the fix).
      const reg = await app.request("http://localhost/v1/register-url");
      expect(reg.status).toBe(200);
      const { code } = (await reg.json()) as { code: string };
      expect(typeof code).toBe("string");

      // Exchange the code → returns the HMAC secret and seals the webhook.
      const ex = await app.request("http://localhost/v1/exchange", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ code }),
      });
      expect(ex.status).toBe(200);
      expect((await ex.json()).hmacSecret).toBeTruthy();
      expect(await isBound(ctx.storage)).toBe(true);

      // Sealed: register-url with no / wrong admin secret is forbidden.
      expect((await app.request("http://localhost/v1/register-url")).status).toBe(403);
      expect(
        (await app.request("http://localhost/v1/register-url", {
          headers: { "x-tv-admin-secret": "wrong" },
        })).status,
      ).toBe(403);

      // Correct admin secret re-opens the setup endpoint.
      expect(
        (await app.request("http://localhost/v1/register-url", {
          headers: { "x-tv-admin-secret": "admin-xyz" },
        })).status,
      ).toBe(200);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("FS adapter — in-place upgrade / redeploy", () => {
  it("preserves webhookId, seal state, and token data across a redeploy of the same store", async () => {
    const dir = await mkdtemp(join(tmpdir(), "wh-redeploy-"));
    try {
      // First deploy: provision identity, store a credential, seal.
      const ctx1 = await fsCtx(dir);
      const id1 = await ctx1.secrets.webhookId();
      await ctx1.storage.set("tokens", "github", { serviceName: "github", secret: "s1" });
      await markBound(ctx1.storage);
      await runStartup(ctx1);

      // Redeploy: a fresh pair of adapters over the SAME files (what `wrangler
      // deploy` / a container restart does — same seed/secret + same store).
      const ctx2 = await fsCtx(dir);
      await runStartup(ctx2);

      expect(await ctx2.secrets.webhookId()).toBe(id1); // identity stable
      expect(await isBound(ctx2.storage)).toBe(true); // still sealed
      expect(await ctx2.storage.get("tokens", "github")).toMatchObject({ secret: "s1" }); // data intact
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("FS adapter — boot schema migration (upconvert-on-load)", () => {
  it("stamps the current schema version on a pre-migration store without losing data", async () => {
    const dir = await mkdtemp(join(tmpdir(), "wh-migrate-"));
    try {
      const ctx = await fsCtx(dir);
      // Pre-migration deployment: a credential exists but schema_state was never
      // stamped (older webhook that predates the migration mechanism).
      await ctx.storage.set("tokens", "github", { serviceName: "github", secret: "old" });
      expect(await ctx.storage.get("meta", "schema_state")).toBeNull();

      const res = await applyPendingMigrations(ctx.storage);

      expect(res.to).toBe(CURRENT_SCHEMA_VERSION);
      expect(await ctx.storage.get("meta", "schema_state")).toMatchObject({
        version: CURRENT_SCHEMA_VERSION,
      });
      // Upconvert is non-destructive — existing credentials survive.
      expect(await ctx.storage.get("tokens", "github")).toMatchObject({ secret: "old" });
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
