// Health endpoint (metadata.py:13-43). GET + HEAD are unauthenticated (TV warms
// the connection with a HEAD probe — tokens.py:181); POST requires HMAC. All
// report the same capability list as /v1/exchange (derived from the registry).

import { corsHeaders, preflightResponse } from "../core/middleware/cors.ts";
import { hmacAuth } from "../core/middleware/hmacAuth.ts";
import { WEBHOOK_VERSION } from "../core/protocol/types.ts";
import type { FeatureModule } from "../core/registry.ts";

export function healthModule(): FeatureModule {
  const startMs = Date.now();

  return {
    name: "health",
    register(app, ctx, registry) {
      const payload = async () => ({
        status: "healthy",
        version: WEBHOOK_VERSION,
        keyConfigured: await ctx.secrets.isConfigured(),
        capabilities: registry.capabilities,
        uptime: Math.floor((Date.now() - startMs) / 1000),
        tokenCount: (await ctx.storage.entries("tokens")).length,
      });

      // GET is unauthenticated and reflects the request Origin so the TV bind
      // UI's in-browser liveness probe isn't CORS-blocked. The payload is
      // non-sensitive (status/version/capabilities/uptime/tokenCount) and already
      // public on GET — CORS only lets a browser read what anyone can already curl.
      app.options("/v1/health", (c) => preflightResponse(c));
      app.get("/v1/health", async (c) => c.json(await payload(), 200, corsHeaders(c.req.header("origin"))));

      // HEAD must be answered explicitly — Hono does not derive it from GET.
      app.on("HEAD", "/v1/health", (c) => c.body(null, 200, corsHeaders(c.req.header("origin"))));

      // POST is the authenticated health check TV uses to re-sync capabilities.
      app.post("/v1/health", hmacAuth(ctx), async (c) => c.json(await payload()));
    },
  };
}
