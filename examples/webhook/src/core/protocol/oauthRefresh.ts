// Webhook-owned OAuth refresh: the one place a stored refresh token is sent to
// a provider. Used by /v1/refresh-notify (TV's manual Refresh), the scheduled
// sweep (Workers cron / Node timer) and the on-demand refresh of an expired
// token at fetch time, so all three refresh, record and fail the same way.
//
// Trust rules (unchanged from refresh-notify):
//   - The client secret comes from LOCAL provider config only, never from a
//     request or a stored hint.
//   - It is only ever sent to a token URL from local config or the built-in
//     table; a stored or TV-supplied token URL that differs is refused.
//   - The TV-supplied hint may name the provider (and a non-secret client id
//     when local config has none); the token's own `oauth` hint outranks it.
//
// What a refresh keeps: every metadata field of the stored document (its
// creationId in particular, which credential/proxy tickets are checked
// against) and every other encrypted field. It replaces the access token, the
// refresh token when the provider rotated it, expiryTime, and stamps
// updatedAt + lastRefreshed. A failure leaves the credential untouched and
// records only a short, non-secret marker in meta (refreshError,
// refreshFailedAt, refreshReconnect) that a later success clears.

import { decryptTokenField, buildEncryptedTokenDocument, EXTRA_SENSITIVE_FIELDS } from "./tokendoc.ts";
import { BUILTIN_TOKEN_AUTH, BUILTIN_TOKEN_URLS, providerEntry, type TokenAuthMethod } from "./oauthConnect.ts";
import { SENSITIVE_FIELDS } from "./types.ts";
import type { Bytes } from "../crypto/encoding.ts";
import type { OAuthProviderConfig, RuntimeContext, StoredDocument } from "../../runtime/context.ts";

export const TOKEN_ENDPOINT_TIMEOUT_MS = 10_000;

/** Default scheduled-refresh window: renew once a token expires within 20 minutes. */
export const DEFAULT_REFRESH_WINDOW_SECONDS = 1200;

/** On-demand refresh at fetch time kicks in this close to expiry. */
export const ON_DEMAND_REFRESH_SKEW_MS = 60_000;

/**
 * Hands a promise to the runtime to keep alive after the response (Workers'
 * `waitUntil`); on Node a detached promise is enough.
 */
export type BackgroundRunner = (task: Promise<unknown>) => void;

/**
 * Services with a background refresh running in this isolate/process. A guard
 * against duplicate work only: no promise is shared between requests, because
 * on Workers a promise started by one request can stall if that request is
 * cancelled (see runtime/worker.ts).
 */
const refreshing = new Map<string, number>(); // service -> start time (ms)
/** A background refresh that has not settled after this long is treated as lost. */
const BACKGROUND_REFRESH_STALE_MS = 60_000;

/** OAuth error codes that only a new consent fixes (the grant was revoked or expired). */
const RECONNECT_ERRORS = new Set(["invalid_grant", "bad_refresh_token"]);

/** Meta keys a refresh owns; a success clears the failure markers. */
const FAILURE_KEYS = ["refreshError", "refreshFailedAt", "refreshReconnect"] as const;

function nowIso(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

/** A provider's error code, if it is a short token (never its free-text description). */
function errorCode(raw: unknown, fallback: string): string {
  return typeof raw === "string" && /^[A-Za-z0-9_.-]{1,64}$/.test(raw) ? raw : fallback;
}

/** expires_in as seconds; some providers send it as a numeric string. */
export function parseExpiresIn(raw: unknown): number | null {
  const n = typeof raw === "string" && raw.trim() !== "" ? Number(raw) : raw;
  return typeof n === "number" && Number.isFinite(n) && n > 0 ? n : null;
}

export interface TokenSet {
  accessToken: string;
  refreshToken: string | null;
  expiresIn: number | null;
  scope: string | null;
}

export type TokenEndpointResult =
  | { ok: true; tokens: TokenSet }
  | { ok: false; error: string; transient: boolean };

export function tokenAuthMethod(provider: string, local: OAuthProviderConfig | undefined): TokenAuthMethod {
  return local?.tokenAuthMethod ?? providerEntry(BUILTIN_TOKEN_AUTH, provider) ?? "client_secret_post";
}

/**
 * POST a grant to a token endpoint and parse the answer. Never throws: a
 * network failure, a timeout, a non-JSON body, an error body (GitHub answers
 * errors with HTTP 200) or a body without an access token all come back as
 * `{ok: false}` with a short code.
 */
export async function postTokenRequest(
  tokenUrl: string,
  grant: Record<string, string>,
  client: { clientId: string; clientSecret: string; method: TokenAuthMethod },
): Promise<TokenEndpointResult> {
  const form = new URLSearchParams(grant);
  const headers: Record<string, string> = {
    "content-type": "application/x-www-form-urlencoded",
    accept: "application/json",
  };
  if (client.method === "client_secret_basic") {
    // RFC 6749 §2.3.1: form-encode each part, then base64 "id:secret".
    headers.authorization = `Basic ${btoa(`${encodeURIComponent(client.clientId)}:${encodeURIComponent(client.clientSecret)}`)}`;
  } else {
    form.set("client_id", client.clientId);
    form.set("client_secret", client.clientSecret);
  }

  let resp: Response;
  try {
    resp = await fetch(tokenUrl, {
      method: "POST",
      headers,
      body: form,
      redirect: "error", // the secret/code/refresh token must not follow a redirect
      signal: AbortSignal.timeout(TOKEN_ENDPOINT_TIMEOUT_MS),
    });
  } catch {
    return { ok: false, error: "provider_unreachable", transient: true };
  }

  let body: Record<string, unknown> | null = null;
  try {
    const parsed: unknown = await resp.json();
    if (parsed && typeof parsed === "object") body = parsed as Record<string, unknown>;
  } catch {
    body = null;
  }

  const transientStatus = resp.status >= 500 || resp.status === 429;
  if (body && body.error != null) {
    return { ok: false, error: errorCode(body.error, "provider_error"), transient: transientStatus };
  }
  if (!resp.ok) return { ok: false, error: `http_${resp.status}`, transient: transientStatus };
  if (!body || typeof body.access_token !== "string" || !body.access_token) {
    return { ok: false, error: "invalid_response", transient: true };
  }
  return {
    ok: true,
    tokens: {
      accessToken: body.access_token,
      refreshToken: typeof body.refresh_token === "string" && body.refresh_token ? body.refresh_token : null,
      expiresIn: parseExpiresIn(body.expires_in),
      scope: typeof body.scope === "string" && body.scope ? body.scope : null,
    },
  };
}

export interface RefreshHint {
  provider?: string;
  tokenUrl?: string;
  clientId?: string;
}

export type RefreshResult =
  | { status: "refreshed"; expiryTime: number }
  | { status: "no_token" }
  | { status: "no_refresh_token" }
  /** No local client credentials for this provider: nothing to refresh with. */
  | { status: "not_configured" }
  /** The stored or TV-supplied hint disagrees with local config: refused, nothing sent. */
  | { status: "config_mismatch"; message: string }
  | { status: "refresh_failed"; error: string; reconnect: boolean };

/** The document's metadata: `meta` of an encrypted doc, top-level non-secret fields of a plaintext one. */
export function docMeta(doc: StoredDocument): Record<string, unknown> {
  if ("fields" in doc) {
    return doc.meta && typeof doc.meta === "object" ? { ...(doc.meta as Record<string, unknown>) } : {};
  }
  const meta: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(doc)) {
    if (k !== "id" && !SENSITIVE_FIELDS.has(k)) meta[k] = v;
  }
  return meta;
}

async function readRefreshToken(key: Bytes, doc: StoredDocument): Promise<string | null> {
  if ("fields" in doc) return decryptTokenField(key, doc, "refreshToken");
  return doc.refreshToken != null && doc.refreshToken !== "" ? String(doc.refreshToken) : null;
}

/** A value that changes on every write of the refresh token (ciphertexts use a fresh IV). */
function refreshFingerprint(doc: StoredDocument | null): unknown {
  if (!doc) return null;
  if ("fields" in doc) return ((doc.fields ?? {}) as Record<string, unknown>).refreshToken ?? null;
  return doc.refreshToken ?? null;
}

/**
 * If the token was refreshed, replaced or deleted by someone else since
 * `before` was read, the outcome to report instead of ours; null if unchanged.
 */
async function concurrentOutcome(ctx: RuntimeContext, service: string, before: StoredDocument): Promise<RefreshResult | null> {
  const now = await ctx.storage.get("tokens", service);
  if (!now) return { status: "no_token" };
  if (refreshFingerprint(now) === refreshFingerprint(before) && docMeta(now).updatedAt === docMeta(before).updatedAt) {
    return null;
  }
  return { status: "refreshed", expiryTime: Number(docMeta(now).expiryTime) || 0 };
}

/**
 * Write a refresh's result only if the stored document is still the one the
 * refresh started from. Returns null when written; otherwise a result describing
 * what is stored now (deleted: no_token), and the refresh result is dropped, so a
 * delete or replace that lands mid-refresh is never overwritten or resurrected.
 */
async function storeUnlessChanged(
  ctx: RuntimeContext,
  service: string,
  before: StoredDocument,
  next: StoredDocument,
): Promise<RefreshResult | null> {
  if (!ctx.storage.setIfUnchanged) {
    await ctx.storage.set("tokens", service, next);
    return null;
  }
  if (await ctx.storage.setIfUnchanged("tokens", service, before, next)) return null;
  return (await concurrentOutcome(ctx, service, before)) ?? { status: "no_token" };
}

/** Rebuild the document with new tokens, keeping every other encrypted field. */
async function rebuild(
  key: Bytes,
  doc: StoredDocument,
  accessToken: string,
  refreshToken: string,
  meta: Record<string, unknown>,
): Promise<StoredDocument> {
  delete meta.hasRefreshToken; // recomputed from the refresh token
  if ("fields" in doc) {
    const out = await buildEncryptedTokenDocument(key, accessToken, refreshToken, meta);
    const fields = { ...((doc.fields ?? {}) as Record<string, string>), ...(out.fields as Record<string, string>) };
    const outMeta = out.meta as Record<string, unknown>;
    outMeta.hasCertificate = "certificateData" in fields;
    outMeta.hasPrivateKey = "privateKeyData" in fields;
    outMeta.hasSSHKey = "sshPrivateKey" in fields;
    outMeta.hasTotpSecret = "totpSecret" in fields;
    return { ...out, fields };
  }
  const extra: Record<string, unknown> = {};
  for (const f of EXTRA_SENSITIVE_FIELDS) if (doc[f] != null) extra[f] = doc[f];
  return buildEncryptedTokenDocument(key, accessToken, refreshToken, meta, extra);
}

/**
 * Refresh one stored token with the webhook's own client credentials.
 * `hint` is the TV-supplied refresh hint (refresh-notify only).
 */
export async function refreshStoredToken(
  ctx: RuntimeContext,
  service: string,
  hint: RefreshHint = {},
): Promise<RefreshResult> {
  const doc = await ctx.storage.get("tokens", service);
  if (!doc) return { status: "no_token" };

  const key = await ctx.secrets.encryptionKey();
  const refreshToken = await readRefreshToken(key, doc);
  if (!refreshToken) return { status: "no_refresh_token" };

  const meta = docMeta(doc);
  // A token minted by this webhook's own /v1/oauth/callback records a
  // non-secret `oauth` hint; it outranks the TV-supplied hint (which can
  // only describe TV's built-in providers).
  const stored = (meta.oauth && typeof meta.oauth === "object" ? meta.oauth : {}) as RefreshHint;
  const provider = (stored.provider ?? hint.provider ?? "").toLowerCase();
  const local = providerEntry(ctx.config.oauthProviders, provider);
  const clientSecret = local?.clientSecret;
  const tokenUrl = local?.tokenUrl ?? providerEntry(BUILTIN_TOKEN_URLS, provider);
  const clientId = local?.clientId ?? stored.clientId ?? hint.clientId;

  if (clientSecret && tokenUrl) {
    for (const claimed of [stored.tokenUrl, hint.tokenUrl]) {
      if (claimed && claimed !== tokenUrl) {
        return { status: "config_mismatch", message: "Token URL does not match this webhook's provider config" };
      }
    }
    // The webhook's own record of the client that minted the token must
    // match the configured one (the TV hint's id is TV's, so it is not checked).
    if (local?.clientId && stored.clientId && stored.clientId !== local.clientId) {
      return { status: "config_mismatch", message: "Client id does not match this webhook's provider config" };
    }
  }
  if (!tokenUrl || !clientId || !clientSecret) return { status: "not_configured" };

  const result = await postTokenRequest(
    tokenUrl,
    { grant_type: "refresh_token", refresh_token: refreshToken },
    { clientId, clientSecret, method: tokenAuthMethod(provider, local) },
  );

  if (!result.ok) {
    // A concurrent refresh (cron vs. fetch vs. manual) may have rotated the
    // refresh token we used: the provider then refuses ours, but the token is
    // fine. Only record a failure against the version we actually tried.
    const concurrent = await concurrentOutcome(ctx, service, doc);
    if (concurrent) return concurrent;
    const reconnect = RECONNECT_ERRORS.has(result.error);
    const failed: StoredDocument = "fields" in doc
      ? { ...doc, meta: { ...meta, refreshError: result.error, refreshFailedAt: nowIso(), refreshReconnect: reconnect } }
      : { ...doc, refreshError: result.error, refreshFailedAt: nowIso(), refreshReconnect: reconnect };
    const kept = await storeUnlessChanged(ctx, service, doc, failed);
    if (kept) return kept;
    return { status: "refresh_failed", error: result.error, reconnect };
  }

  const { tokens } = result;
  // Providers that do not rotate (Google, often Spotify) omit refresh_token:
  // the one we have stays valid.
  const newRefresh = tokens.refreshToken ?? refreshToken;
  const expiryTime = Date.now() + (tokens.expiresIn ?? 3600) * 1000;
  const now = nowIso();

  // Never overwrite a token that changed while we were at the provider (a
  // reconnect, or a concurrent refresh that already stored newer tokens). A
  // concurrent *failure* (its marker landed first, refresh token untouched) is
  // not such a change: our rotated tokens must win, so retry on top of it.
  let base = doc;
  for (let attempt = 0; ; attempt++) {
    const current = attempt === 0 ? base : await ctx.storage.get("tokens", service);
    if (!current) return { status: "no_token" };
    if (attempt > 0) {
      const cur = docMeta(current);
      if (refreshFingerprint(current) !== refreshFingerprint(doc) || cur.updatedAt !== docMeta(doc).updatedAt) {
        return { status: "refreshed", expiryTime: Number(cur.expiryTime) || 0 };
      }
      base = current;
    }
    const nextMeta = docMeta(base);
    for (const k of FAILURE_KEYS) delete nextMeta[k];
    Object.assign(nextMeta, {
      serviceName: nextMeta.serviceName ?? service,
      tokenType: nextMeta.tokenType ?? (provider || "oauth"),
      expiryTime,
      updatedAt: now,
      lastRefreshed: now,
    });
    if (tokens.scope) nextMeta.scope = tokens.scope;
    const next = await rebuild(key, base, tokens.accessToken, newRefresh, nextMeta);

    if (attempt === 0) {
      const concurrent = await concurrentOutcome(ctx, service, doc);
      if (concurrent) return concurrent;
    }
    if (!ctx.storage.setIfUnchanged) {
      await ctx.storage.set("tokens", service, next);
      return { status: "refreshed", expiryTime };
    }
    if (await ctx.storage.setIfUnchanged("tokens", service, base, next)) return { status: "refreshed", expiryTime };
    if (attempt >= 3) return (await concurrentOutcome(ctx, service, doc)) ?? { status: "no_token" };
  }
}

/** Whether the webhook may refresh this token on its own (no TV request involved). */
export function selfRefreshable(meta: Record<string, unknown>): boolean {
  return (
    !!meta.oauth &&
    typeof meta.oauth === "object" &&
    meta.hasRefreshToken !== false &&
    meta.refreshReconnect !== true &&
    typeof meta.expiryTime === "number" &&
    meta.expiryTime > 0
  );
}

export interface SweepSummary {
  checked: number;
  refreshed: number;
  failed: number;
  skipped: number;
}

/**
 * The scheduled sweep: refresh every own-app token (one with a stored `oauth`
 * hint, i.e. minted by /v1/oauth/callback) that expires within the window.
 * Tokens without the hint (pasted, or minted with Token Vault's legacy
 * client) are left alone: this webhook may not hold the client they belong to.
 * A token marked as needing a reconnect is skipped until it is reconnected or
 * a manual refresh succeeds. One token's failure never stops the others.
 */
export async function refreshDueTokens(ctx: RuntimeContext, now: number = Date.now()): Promise<SweepSummary> {
  const summary: SweepSummary = { checked: 0, refreshed: 0, failed: 0, skipped: 0 };
  // No own-app providers configured (OAUTH_PROVIDERS_JSON unset): nothing here
  // can be refreshed, so don't load every stored token just to skip it.
  if (Object.keys(ctx.config.oauthProviders ?? {}).length === 0) return summary;
  if (!(await ctx.secrets.isConfigured())) return summary;
  const windowMs = (ctx.config.refreshWindowSeconds ?? DEFAULT_REFRESH_WINDOW_SECONDS) * 1000;

  for (const [service, doc] of await ctx.storage.entries("tokens")) {
    const meta = docMeta(doc);
    if (!selfRefreshable(meta)) continue;
    if ((meta.expiryTime as number) - now > windowMs) continue;
    summary.checked++;
    try {
      const r = await refreshStoredToken(ctx, service);
      if (r.status === "refreshed") summary.refreshed++;
      else if (r.status === "refresh_failed" || r.status === "config_mismatch") {
        summary.failed++;
        console.warn(`[refresh] ${service}: ${r.status === "refresh_failed" ? r.error : "config_mismatch"}`);
      } else summary.skipped++;
    } catch {
      summary.failed++;
      console.error(`[refresh] ${service}: unexpected failure`);
    }
  }
  if (summary.checked) console.log(`[refresh] sweep: ${JSON.stringify(summary)}`);
  return summary;
}

/**
 * Fetch-time safety net: if an own-app token is expired (or about to be),
 * refresh it before handing it out. Best effort: on any failure the stored
 * document is returned unchanged, exactly as before this existed.
 */
export async function freshDocument(
  ctx: RuntimeContext,
  service: string,
  doc: StoredDocument,
  background?: BackgroundRunner,
): Promise<StoredDocument> {
  const meta = docMeta(doc);
  const left = (meta.expiryTime as number) - Date.now();
  if (!selfRefreshable(meta) || left > ON_DEMAND_REFRESH_SKEW_MS) return doc;

  // Inside the skew but not yet expired: the stored token still works, so serve
  // it now and refresh behind the response. A refresh stampede (every request in
  // the last minute blocking on its own refresh) becomes one detached refresh per
  // service per isolate. Already expired: refresh before answering, as before.
  if (left > 0) {
    const startedAt = refreshing.get(service);
    if (startedAt === undefined || Date.now() - startedAt > BACKGROUND_REFRESH_STALE_MS) {
      refreshing.set(service, Date.now());
      const task = refreshStoredToken(ctx, service)
        .catch(() => undefined) // best effort: the sweep and the next request retry
        .finally(() => refreshing.delete(service));
      (background ?? ((p) => void p))(task);
    }
    return doc;
  }
  try {
    const r = await refreshStoredToken(ctx, service);
    if (r.status === "refreshed") {
      const fresh = await ctx.storage.get("tokens", service);
      // The caller checked its ticket against `doc`. If the credential was
      // replaced (a new creationId) between that check and this read, serve the
      // document the ticket was checked against, never the new one.
      if (fresh && docMeta(fresh).creationId === meta.creationId) return fresh;
    }
  } catch {
    // fall through: serve what is stored
  }
  return doc;
}
