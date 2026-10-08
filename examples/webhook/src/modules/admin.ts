// HMAC-authenticated admin endpoints (no capability advertised).
//   POST /v1/admin/migrate  one-shot sweep that migrates every stored token whose
//   meta still holds a plaintext otpauth:// URI (seed -> encrypted totpSecret,
//   descriptors -> meta). Idempotent. Response carries counts only.

import { hmacAuth } from "../core/middleware/hmacAuth.ts";
import { sendError } from "../core/middleware/respond.ts";
import { migrateAllTotp } from "../core/protocol/totpHeal.ts";
import type { FeatureModule } from "../core/registry.ts";

export function adminModule(): FeatureModule {
  return {
    name: "admin",
    register(app, ctx) {
      app.post("/v1/admin/migrate", hmacAuth(ctx), async (c) => {
        try {
          const result = await migrateAllTotp(ctx, ctx.rawStorage ?? ctx.storage);
          return c.json({ status: "ok", totp: result });
        } catch (e) {
          return sendError(c, e);
        }
      });
    },
  };
}
