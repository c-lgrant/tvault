// Builds the runtime-neutral Hono app: raw-body capture, module registration,
// and a JSON error boundary. Both runtime entry points (node.ts, worker.ts)
// construct a RuntimeContext + module list and call this.

import { Hono } from "hono";
import type { Bytes } from "./crypto/encoding.ts";
import type { RuntimeContext } from "../runtime/context.ts";
import { buildRegistryView, type FeatureModule } from "./registry.ts";
import { rawBody } from "./middleware/rawbody.ts";
import { sendError } from "./middleware/respond.ts";

/** Hono context variables shared across middleware + handlers. */
export interface AppVariables {
  rawBody: Bytes;
}

export type AppEnv = { Variables: AppVariables };

export function createApp(ctx: RuntimeContext, modules: FeatureModule[]): Hono<AppEnv> {
  const app = new Hono<AppEnv>();

  // Capture raw bytes for every request before any handler parses them.
  app.use("*", rawBody());

  const registry = buildRegistryView(modules);
  for (const m of modules) m.register?.(app, ctx, registry);

  // Safety net: any thrown WebhookError (or unexpected error) becomes a
  // spec-compliant {error,message} envelope. Browser endpoints attach their own
  // CORS headers and handle errors inline, so this is for the HMAC paths.
  app.onError((err, c) => sendError(c, err));

  return app;
}
