// Shared env → WebhookConfig builder. Both runtimes read the same variable
// names: Node passes process.env, the Worker passes its string bindings.
//
//   TOKENVAULT_FRONTEND_URL  TV frontend origin (for the bind/register URL)
//   WEBHOOK_EXTERNAL_URL / EXTERNAL_URL  this webhook's public URL
//   TIMESTAMP_TOLERANCE      override the 300s default
//   DENY_IPS, DENY_ORIGINS   comma-separated denylists (credential/store/totp)
//   TOKENVAULT_IP            TV egress IP, folded into DENY_IPS
//   OAUTH_PROVIDERS_JSON     provider→{clientSecret,clientId?,tokenUrl?} map

import { TIMESTAMP_TOLERANCE, WEBHOOK_VERSION } from "../core/protocol/types.ts";
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
    if (parsed && typeof parsed === "object") return parsed;
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

  return {
    version: WEBHOOK_VERSION,
    timestampTolerance: Number.isFinite(tolerance) && tolerance > 0 ? tolerance : TIMESTAMP_TOLERANCE,
    tokenvaultFrontendUrl: get("TOKENVAULT_FRONTEND_URL") ?? "https://tokenvault.uk",
    denyIps,
    denyOrigins: csv(get("DENY_ORIGINS")),
    // Omit optional keys entirely when unset (exactOptionalPropertyTypes).
    ...(externalUrl ? { externalUrl } : {}),
    ...(oauthProviders ? { oauthProviders } : {}),
  };
}
