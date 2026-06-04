// Node.js entry point — container runtime, fronted by ngrok or Cloudflare Tunnel
// (see entrypoint.sh). Builds a RuntimeContext from env + the file-backed
// adapters and serves the shared Hono app with @hono/node-server.
//
// Key material lives on disk under /data (FileSecretProvider) and never leaves
// this host; the control plane only ever learns the HMAC secret via the
// one-time /v1/exchange handshake.

import { serve } from "@hono/node-server";
import { createApp } from "../core/app.ts";
import { allModules } from "../modules/index.ts";
import { FsStorageAdapter } from "../adapters/storage/fs.ts";
import { FileSecretProvider } from "../adapters/secrets/fileSecret.ts";
import { MemoryReplayGuard } from "../adapters/replay/memory.ts";
import { configFromEnv } from "./config.ts";

async function main(): Promise<void> {
  const [storage, secrets] = await Promise.all([FsStorageAdapter.create(), FileSecretProvider.create()]);
  const ctx = {
    config: configFromEnv((k) => process.env[k]),
    secrets,
    storage,
    replay: new MemoryReplayGuard(),
  };

  const app = createApp(ctx, allModules());

  const port = Number(process.env.PORT) || 8080;
  serve({ fetch: app.fetch, port, hostname: "0.0.0.0" });
  console.log(`tv-webhook (node) listening on :${port} — webhookId=${await secrets.webhookId()}`);
}

main().catch((err) => {
  console.error("fatal: failed to start tv-webhook", err);
  process.exit(1);
});
