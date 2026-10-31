// OAuth "connect with your own app" primitives: the state ticket's purpose,
// the PKCE derivation, and the built-in provider table.
//
// The control plane builds the provider's authorize URL and signs a one-shot
// state ticket (same `base64url(json).hex_hmac` scheme as every other ticket).
// The provider redirects the browser to this webhook's /v1/oauth/callback, so
// the authorization code never reaches the control plane.
//
// PKCE: the code_verifier is NOT carried by the browser. Both sides derive it
// from the shared HMAC secret and the ticket nonce:
//
//   verifier  = base64url_nopad( HMAC-SHA256(hmacSecret, "tv-oauth-pkce-v1:" + nonce) )   // 43 chars
//   challenge = base64url_nopad( SHA-256( ascii(verifier) ) )                              // S256
//
// so a state ticket seen in the browser history or a proxy log does not reveal
// the verifier.

import { base64UrlEncodeNoPad, type Bytes, utf8 } from "../crypto/encoding.ts";

/** `pur` value of the state ticket. */
export const OAUTH_CONNECT_PURPOSE = "oauth_connect";

/** Path of the callback this webhook serves; the user registers `<webhook>` + this at the provider. */
export const OAUTH_CALLBACK_PATH = "/v1/oauth/callback";

/** Advertised at /v1/exchange and /v1/health. */
export const OAUTH_CALLBACK_CAPABILITY = "oauth-callback";

/** State tickets live 10 minutes (the user is at the provider's consent screen meanwhile). */
export const OAUTH_STATE_TTL_SECONDS = 600;

const PKCE_INFO_PREFIX = "tv-oauth-pkce-v1:";

export async function derivePkceVerifier(hmacSecret: Bytes, nonce: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", hmacSecret, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, utf8(PKCE_INFO_PREFIX + nonce)));
  return base64UrlEncodeNoPad(mac);
}

export async function pkceChallenge(verifier: string): Promise<string> {
  return base64UrlEncodeNoPad(new Uint8Array(await crypto.subtle.digest("SHA-256", utf8(verifier))));
}

/** Start path: the browser lands here first so the flow can be bound to it with a cookie. */
export const OAUTH_START_PATH = "/v1/oauth/start";

/** Cookie binding the browser that started the flow to the callback. Value: sha256 hex of the state nonce. */
export const OAUTH_COOKIE = "tv_oauth_state";

/**
 * Token endpoints the webhook will send a client secret to without being told
 * so locally. Deliberately a fixed table: a state ticket's, refresh hint's or
 * stored hint's token URL is only ever cross-checked against it (or against the
 * operator's OAUTH_PROVIDERS_JSON `tokenUrl`), never trusted, so a compromised
 * control plane cannot point the client secret at a server of its choosing.
 */
export const BUILTIN_TOKEN_URLS: Readonly<Record<string, string>> = {
  google: "https://oauth2.googleapis.com/token",
  github: "https://github.com/login/oauth/access_token",
  spotify: "https://accounts.spotify.com/api/token",
};

/** Authorize endpoints (and fixed extra params) the webhook builds the provider redirect from. */
export const BUILTIN_AUTHORIZE: Readonly<Record<string, { url: string; extra: Record<string, string> }>> = {
  google: { url: "https://accounts.google.com/o/oauth2/v2/auth", extra: { access_type: "offline", prompt: "consent" } },
  github: { url: "https://github.com/login/oauth/authorize", extra: {} },
  spotify: { url: "https://accounts.spotify.com/authorize", extra: {} },
};

export async function sha256Hex(s: string): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", utf8(s)));
  return Array.from(d, (b) => b.toString(16).padStart(2, "0")).join("");
}
