// Advertises the `ticketConstraints` capability: this webhook honours the
// optional store-ticket fields `mode` ("create"|"overwrite") and `cid`, and the
// credential/proxy-ticket field `cid`. Enforcement lives in store/credential/
// proxy/totp via core/protocol/constraints.ts; this module only advertises it.

import type { FeatureModule } from "../core/registry.ts";

export function ticketConstraintsModule(): FeatureModule {
  return { name: "ticketConstraints", capability: "ticketConstraints" };
}
