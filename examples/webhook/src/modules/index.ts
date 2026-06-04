// Canonical module assembly. The registration order fixes the advertised
// capability list (buildRegistryView preserves order) so /v1/exchange and
// /v1/health report exactly:
//   ["store","credential","proxy","refresh","tv-refresh","storage","totp"]
// matching the TV backend's CAPABILITIES set. Interceptor order also follows
// from here: TOTP is registered before GCP, so a TOTP token is intercepted
// first (the two are mutually exclusive, but this mirrors the reference).

import type { FeatureModule } from "../core/registry.ts";
import { storeModule } from "./store.ts";
import { credentialModule } from "./credential.ts";
import { proxyModule } from "./proxy.ts";
import { refreshNotifyModule } from "./refreshNotify.ts";
import { tvRefreshModule } from "./tvRefresh.ts";
import { storageModule } from "./storage.ts";
import { totpModule } from "./interceptors/totp.ts";
import { gcpSaModule } from "./interceptors/gcpSa.ts";
import { healthModule } from "./health.ts";
import { exchangeModule } from "./exchange.ts";

/** Every feature module, in the order that yields the canonical capability list. */
export function allModules(): FeatureModule[] {
  return [
    // Capability-bearing modules, in canonical order.
    storeModule(),
    credentialModule(),
    proxyModule(),
    refreshNotifyModule(),
    tvRefreshModule(),
    storageModule(),
    totpModule(),
    // Transparent interceptor (no capability).
    gcpSaModule(),
    // Infra endpoints (no capability).
    healthModule(),
    exchangeModule(),
  ];
}
