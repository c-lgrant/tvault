// Feature-module registry. A module contributes at most one capability string,
// optionally a credential interceptor, and optionally routes. New webhook
// features are added as new modules — no edits to the core or other modules.
//
// The advertised capability list is derived from the registered modules so that
// /v1/exchange and /v1/health always report the same set (tokens.py:1420-1432
// re-syncs capabilities from /v1/health, so the two MUST agree).

import type { Hono } from "hono";
import type { RuntimeContext, StoredDocument } from "../runtime/context.ts";
import type { AppEnv } from "./app.ts";

/** Input handed to a credential interceptor when its `matches` returns true. */
export interface InterceptorInput {
  /** The flattened plaintext token object (decrypted fields merged with meta). */
  token: Record<string, unknown>;
  service: string;
  /** The raw stored document (for format-specific metadata like TOTP period). */
  storedDoc: StoredDocument;
  /** Request query params (e.g. GCP `scopes`). */
  query: URLSearchParams;
  ctx: RuntimeContext;
}

/**
 * Transforms a credential at retrieval time — e.g. TOTP secret → live code,
 * GCP SA key → minted access token. The first matching interceptor wins.
 */
export interface CredentialInterceptor {
  name: string;
  matches(token: Record<string, unknown>, storedDoc: StoredDocument): boolean;
  transform(input: InterceptorInput): Promise<Record<string, unknown>>;
}

export interface RegistryView {
  capabilities: string[];
  interceptors: CredentialInterceptor[];
}

export interface FeatureModule {
  name: string;
  /** Capability advertised at exchange/health; omit for infra-only modules. */
  capability?: string;
  /** Optional credential interceptor contributed by this module. */
  interceptor?: CredentialInterceptor;
  /** Register routes on the shared app. */
  register?(app: Hono<AppEnv>, ctx: RuntimeContext, registry: RegistryView): void;
}

export function buildRegistryView(modules: FeatureModule[]): RegistryView {
  const capabilities: string[] = [];
  const interceptors: CredentialInterceptor[] = [];
  for (const m of modules) {
    if (m.capability && !capabilities.includes(m.capability)) capabilities.push(m.capability);
    if (m.interceptor) interceptors.push(m.interceptor);
  }
  return { capabilities, interceptors };
}
