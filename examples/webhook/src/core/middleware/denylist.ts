// Config-driven origin/IP denylist for the browser-facing credential + store
// endpoints. This is the guard that keeps TV zero-knowledge: a *real*,
// correctly-signed ticket replayed from Token Vault's own server IP must NOT
// return a credential (TV's `credential_real_ticket_wrong_ip` probe asserts
// this). The Python reference lacks this check; it is added here deliberately.

import type { MiddlewareHandler } from "hono";
import type { AppEnv } from "../app.ts";
import type { WebhookConfig } from "../../runtime/context.ts";
import { forbidden } from "../protocol/errors.ts";
import { corsHeaders } from "./cors.ts";
import { sendError } from "./respond.ts";

/** Best-effort client IP, preferring proxy/CDN headers over the raw socket. */
function clientIp(
  cf: string | undefined,
  xff: string | undefined,
  xreal: string | undefined,
): string | undefined {
  return cf || xff?.split(",")[0]?.trim() || xreal || undefined;
}

export function denylist(config: WebhookConfig): MiddlewareHandler<AppEnv> {
  const deniedIps = new Set(config.denyIps);
  const deniedOrigins = new Set(config.denyOrigins);

  return async (c, next) => {
    const origin = c.req.header("origin");
    const ip = clientIp(
      c.req.header("cf-connecting-ip"),
      c.req.header("x-forwarded-for"),
      c.req.header("x-real-ip"),
    );

    if (ip && deniedIps.has(ip)) {
      return sendError(c, forbidden("Access from this address is not permitted"), corsHeaders(origin));
    }
    if (origin && deniedOrigins.has(origin)) {
      return sendError(c, forbidden("Access from this origin is not permitted"), corsHeaders(origin));
    }

    await next();
  };
}
