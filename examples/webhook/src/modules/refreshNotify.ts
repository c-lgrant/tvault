// Autonomous OAuth refresh (refresh.py:187-319). TV notifies the webhook (on a
// manual Refresh); the webhook owns the credential and performs the refresh
// itself. This is the default, fully zero-knowledge refresh path. The same
// refresh also runs on the webhook's own schedule (refreshDueTokens) and at
// fetch time for an expired own-app token (freshDocument).
//
// DIVERGENCE FROM THE PYTHON REFERENCE (deliberate): the client secret is read
// from LOCAL provider config (ctx.config.oauthProviders), NEVER from the
// TV-supplied refresh hint. The reference trusts hint.clientSecret
// (refresh.py:246) — that lets the control plane influence the credential
// exchange, which breaks the trust model. Here the client secret goes only to
// a token URL from local config or the built-in table (google, github,
// spotify); a hint naming any other URL is refused. The hint may supply only
// a non-secret clientId, and only when local config has none.
// See core/protocol/oauthRefresh.ts.
//
// Response statuses are the spec's (llm.txt /v1/refresh-notify). A
// `refresh_failed` from the provider also carries the provider's short OAuth
// error code (`error`, e.g. "invalid_grant") and `reconnectRequired` (true
// when only a new consent fixes it). Both are additive and never secret.

import { hmacAuth } from "../core/middleware/hmacAuth.ts";
import { readJsonBody } from "../core/middleware/body.ts";
import { sendError } from "../core/middleware/respond.ts";
import { invalidRequest } from "../core/protocol/errors.ts";
import { type RefreshHint, refreshStoredToken } from "../core/protocol/oauthRefresh.ts";
import type { FeatureModule } from "../core/registry.ts";

export function refreshNotifyModule(): FeatureModule {
  return {
    name: "refresh-notify",
    capability: "refresh",
    register(app, ctx) {
      app.post("/v1/refresh-notify", hmacAuth(ctx), async (c) => {
        try {
          const body = readJsonBody(c);
          const requestId =
            typeof body.requestId === "string" ? body.requestId : (c.req.header("X-TokenVault-Request-Id") ?? "unknown");
          const service = typeof body.service === "string" ? body.service : "";
          const hint = (body.refreshHint && typeof body.refreshHint === "object" ? body.refreshHint : {}) as RefreshHint;

          if (!service) return sendError(c, invalidRequest("Missing 'service'"));

          const r = await refreshStoredToken(ctx, service, hint);
          switch (r.status) {
            case "refreshed":
              return c.json({ requestId, status: "refreshed", newExpiresAt: new Date(r.expiryTime).toISOString() });
            case "no_token":
              return c.json({ requestId, status: "no_token", message: `No token stored for service '${service}'` });
            case "no_refresh_token":
              return c.json({ requestId, status: "no_refresh_token", message: `No refreshToken found for service '${service}'` });
            case "not_configured":
              // No local credentials to refresh with — acknowledge only.
              return c.json({
                requestId,
                status: "acknowledged",
                message: "Notification received but no local provider credentials for auto-refresh",
              });
            case "config_mismatch":
              return c.json({ requestId, status: "refresh_failed", message: r.message });
            case "refresh_failed":
              return c.json({
                requestId,
                status: "refresh_failed",
                message: `OAuth provider refused the refresh (${r.error})`,
                error: r.error,
                reconnectRequired: r.reconnect,
              });
          }
        } catch (e) {
          return sendError(c, e);
        }
      });
    },
  };
}
