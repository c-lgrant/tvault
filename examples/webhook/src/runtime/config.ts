// Shared env → WebhookConfig builder. Both runtimes read the same variable
// names: Node passes process.env, the Worker passes its string bindings.
//
//   TOKENVAULT_FRONTEND_URL  TV frontend origin (for the bind/register URL)
//   WEBHOOK_EXTERNAL_URL / EXTERNAL_URL  this webhook's public URL
//   TIMESTAMP_TOLERANCE      override the 300s default
//   DENY_IPS, DENY_ORIGINS   comma-separated denylists (credential/store/totp)
//   TOKENVAULT_IP            TV egress IP, folded into DENY_IPS
//   OAUTH_PROVIDERS_JSON     provider→{clientSecret,clientId?,tokenUrl?,authorizeUrl?,
//                            authorizeParams?,tokenAuthMethod?} map
//   OAUTH_REFRESH_WINDOW_SECONDS  scheduled refresh renews own-app tokens expiring
//                            within this window (default 1200)
//   OAUTH_REFRESH_INTERVAL_SECONDS  Node only: how often the refresh sweep runs
//                            (default 600; 0 turns it off). Workers use the cron
//                            trigger in wrangler.toml.
//   AUDIT_RETENTION_DAYS     delete audit events older than this many days (default 0 =
//                            keep everything)
//   TV_MAX_BODY_BYTES      request-body cap before authentication (default 1048576)
//   TV_MAX_PROXY_BODY_BYTES  the same for /v1/proxy (default 16777216)
//   TV_REFRESH_ENABLED    "true" registers the legacy tv-refresh module (default off)
//   TV_PROXY_ALLOWED_ORIGINS  JSON object, service name → list of origins /v1/proxy may
//                            send that credential to ("*" = every service). Unset = no
//                            allowlist. Not valid JSON = the webhook does not start.
//   TV_PROXY_ALLOW_PRIVATE  "true" lets /v1/proxy call private addresses (default off)
//   TV_REPLAY_NONCES      Workers only: "cache" keeps ticket nonces in the per-colo
//                            cache (best effort) instead of D1 (atomic, the default)

import { TIMESTAMP_TOLERANCE, WEBHOOK_VERSION } from "../core/protocol/types.ts";
import { parseProxyAllowedOrigins } from "../core/protocol/upstreamGuard.ts";
import { PROVIDER_SLUG } from "../core/protocol/oauthConnect.ts";
import type { OAuthProviderConfig, WebhookConfig } from "./context.ts";

type Getenv = (key: string) => string | undefined;

function csv(value: string | undefined): string[] {
  return (value ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function parseOAuthProviders(raw: string | undefined): Record<string, OAuthProviderConfig> | undefined {
  if (!raw) return undefined;
  try {
    const parsed = JSON.parse(raw) as Record<string, OAuthProviderConfig>;
    if (parsed && typeof parsed === "object") {
      // Providers are looked up by lower-case name ("Google" would never match).
      // No prototype: a request-supplied name must never resolve to a prototype member.
      const out: Record<string, OAuthProviderConfig> = Object.create(null) as Record<string, OAuthProviderConfig>;
      for (const [name, cfg] of Object.entries(parsed)) {
        const slug = name.toLowerCase();
        if (!PROVIDER_SLUG.test(slug)) {
          console.error("OAUTH_PROVIDERS_JSON has a provider name that is not a valid slug — ignoring it");
          continue;
        }
        out[slug] = cfg;
      }
      return out;
    }
  } catch {
    console.error("OAUTH_PROVIDERS_JSON is not valid JSON — ignoring");
  }
  return undefined;
}

export function configFromEnv(get: Getenv): WebhookConfig {
  // TV's egress IP must be denied on the browser-facing endpoints so a real
  // ticket replayed from TV's server yields nothing.
  const denyIps = csv(get("DENY_IPS"));
  const tvIp = get("TOKENVAULT_IP");
  if (tvIp && !denyIps.includes(tvIp)) denyIps.push(tvIp);

  const tolerance = Number(get("TIMESTAMP_TOLERANCE"));
  const externalUrl = get("WEBHOOK_EXTERNAL_URL") ?? get("EXTERNAL_URL");
  const oauthProviders = parseOAuthProviders(get("OAUTH_PROVIDERS_JSON"));

  // TOKENVAULT_FRONTEND_URL is required — no silent prod fallback.
  // wrangler.toml [vars] must set it; Node deployments must set it in the env.
  const tokenvaultFrontendUrl = get("TOKENVAULT_FRONTEND_URL");
  if (!tokenvaultFrontendUrl) {
    throw new Error(
      "TOKENVAULT_FRONTEND_URL is required. Set it to the Token Vault frontend origin (e.g. https://tokenvault.uk).",
    );
  }

  const adminSecret = get("TV_ADMIN_SECRET");
  const tvRefreshEnabled = get("TV_REFRESH_ENABLED")?.trim().toLowerCase() === "true";

  const ratePerMinute = Number(get("TV_RATE_LIMIT_PER_MINUTE"));
  const rateLimit =
    Number.isFinite(ratePerMinute) && ratePerMinute > 0
      ? { maxPerMinute: Math.floor(ratePerMinute) }
      : undefined;

  const refreshWindow = Number(get("OAUTH_REFRESH_WINDOW_SECONDS"));
  const retentionDays = Number(get("AUDIT_RETENTION_DAYS"));
  const maxBody = Number(get("TV_MAX_BODY_BYTES"));
  const maxProxyBody = Number(get("TV_MAX_PROXY_BODY_BYTES"));
  // Throws when set and unreadable: a broken allowlist must not mean "allow all".
  const proxyAllowedOrigins = parseProxyAllowedOrigins(get("TV_PROXY_ALLOWED_ORIGINS"));
  const proxyAllowPrivate = get("TV_PROXY_ALLOW_PRIVATE")?.trim().toLowerCase() === "true";

  return {
    version: WEBHOOK_VERSION,
    ...(Number.isFinite(refreshWindow) && refreshWindow > 0 ? { refreshWindowSeconds: Math.floor(refreshWindow) } : {}),
    ...(Number.isFinite(retentionDays) && retentionDays > 0 ? { auditRetentionDays: retentionDays } : {}),
    ...(Number.isFinite(maxBody) && maxBody > 0 ? { maxBodyBytes: Math.floor(maxBody) } : {}),
    ...(Number.isFinite(maxProxyBody) && maxProxyBody > 0 ? { maxProxyBodyBytes: Math.floor(maxProxyBody) } : {}),
    timestampTolerance: Number.isFinite(tolerance) && tolerance > 0 ? tolerance : TIMESTAMP_TOLERANCE,
    tokenvaultFrontendUrl,
    denyIps,
    denyOrigins: csv(get("DENY_ORIGINS")),
    // Omit optional keys entirely when unset (exactOptionalPropertyTypes).
    ...(externalUrl ? { externalUrl } : {}),
    ...(oauthProviders ? { oauthProviders } : {}),
    ...(adminSecret ? { adminSecret } : {}),
    ...(rateLimit ? { rateLimit } : {}),
    ...(tvRefreshEnabled ? { tvRefreshEnabled } : {}),
    ...(proxyAllowedOrigins ? { proxyAllowedOrigins } : {}),
    ...(proxyAllowPrivate ? { proxyAllowPrivate } : {}),
  };
}
