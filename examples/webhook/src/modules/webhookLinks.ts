// Shared link/URL resolution for pages that point out from this webhook to
// Token Vault or the Cloudflare dashboard. Used by both the /bind flow
// (exchange.ts) and the / landing page (landing.ts) so the resolution rules
// and the seed-missing fix instructions can't drift between the two.

import type { Context } from "hono";
import type { AppEnv } from "../core/app.ts";
import type { WebhookConfig } from "../runtime/context.ts";

/** This worker's own public URL: the configured EXTERNAL_URL, or derived from
 * the request's Host header when unset. */
export function resolveExternalUrl(c: Context<AppEnv>, config: WebhookConfig): string | null {
  if (config.externalUrl) return config.externalUrl;
  const host = c.req.header("x-forwarded-host") ?? c.req.header("host");
  const proto = c.req.header("x-forwarded-proto") ?? "https";
  return host ? `${proto}://${host}` : null;
}

// The Token Vault frontend to bind to. A `tv` query param lets the launching TV
// instance (dev, prod, or a self-host) point the webhook back at itself, so the
// frontend URL is not hard-coded per deployment. The param is constrained to an
// https origin (http only for localhost) and is SHOWN on the bind page, because
// whoever receives the redirect can exchange the one-time code for the HMAC
// secret — the operator must confirm the destination. No param → the configured
// TOKENVAULT_FRONTEND_URL (the trusted default).
export function resolveFrontend(c: Context<AppEnv>, config: WebhookConfig): string {
  const tv = c.req.query("tv");
  if (tv) {
    try {
      const u = new URL(tv);
      const isLocalhost = u.hostname === "localhost" || u.hostname === "127.0.0.1";
      if (u.protocol === "https:" || (u.protocol === "http:" && isLocalhost)) {
        return `${u.protocol}//${u.host}`;
      }
    } catch {
      // malformed tv param → fall through to the configured default
    }
  }
  return config.tokenvaultFrontendUrl;
}

// Best-effort deep link into the Cloudflare dashboard for THIS worker's settings,
// where TV_WEBHOOK_SEED is set. The worker name is the first label of a
// `*.workers.dev` host; behind a custom domain we can't know it, so fall back to
// the Workers & Pages list. `:account` is a dashboard placeholder Cloudflare
// resolves to the signed-in account, so we don't need the account id.
export function workerNameFromHost(externalUrl: string): string | null {
  try {
    const host = new URL(externalUrl).hostname;
    if (host.endsWith(".workers.dev")) {
      const label = host.split(".")[0];
      return label && label !== "workers" ? label : null;
    }
  } catch {
    /* malformed URL → no name */
  }
  return null;
}

export function dashboardSettingsUrl(workerName: string | null): string {
  return workerName
    ? `https://dash.cloudflare.com/?to=/:account/workers/services/view/${workerName}/production/settings`
    : "https://dash.cloudflare.com/?to=/:account/workers-and-pages";
}

/** Everything needed to tell an operator how to set TV_WEBHOOK_SEED for THIS
 * worker: the dashboard deep link and the exact `wrangler secret put` command,
 * with `--name` baked in when derivable from the host. Shared by the /bind
 * setup page and the / landing page so the fix can't diverge between them. */
export interface SeedFix {
  settingsUrl: string;
  workerName: string | null;
  command: string;
}

export function seedFix(externalUrl: string): SeedFix {
  const workerName = workerNameFromHost(externalUrl);
  const nameFlag = workerName ? ` --name ${workerName}` : "";
  return {
    settingsUrl: dashboardSettingsUrl(workerName),
    workerName,
    command: `openssl rand -hex 32 | npx wrangler secret put TV_WEBHOOK_SEED${nameFlag}`,
  };
}
