// GCP service-account interceptor (gcp.py). When a stored credential is a GCP
// service-account JSON key, mint a short-lived OAuth2 access token instead of
// ever returning the raw key — the agent only sees a ~1h Bearer token.
//
// The Python reference uses the `google-auth` library; that is not portable to
// Cloudflare Workers. This re-implements the SA → access-token exchange with
// WebCrypto only (RS256 JWT assertion → token endpoint), so it runs unchanged
// on Node and Workers. `isGcpServiceAccount` + `mintGcpAccessToken` are also
// imported directly by the proxy module (proxy.py:78-89).

import { base64UrlEncodeNoPad, sha256Hex, utf8 } from "../../core/crypto/encoding.ts";
import { gcpMintFailed } from "../../core/protocol/errors.ts";
import type { CredentialInterceptor, FeatureModule, InterceptorInput } from "../../core/registry.ts";

const DEFAULT_SCOPES = [
  "https://www.googleapis.com/auth/cloud-platform",
  "https://www.googleapis.com/auth/cloud-billing.readonly",
];

const GOOGLE_TOKEN_URI = "https://oauth2.googleapis.com/token";
const JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const TOKEN_ENDPOINT_TIMEOUT_MS = 10_000;

interface ServiceAccountKey {
  type?: string;
  private_key?: string;
  client_email?: string;
  token_uri?: string;
}

export interface MintedToken {
  accessToken: string;
  expiresAt: string;
  expiryTime: number;
  tokenType: "Bearer";
  serviceAccount: string;
}

/** True when a decrypted credential string is a GCP SA JSON key (gcp.py:36-47). */
export function isGcpServiceAccount(credentialValue: string): boolean {
  try {
    const data: unknown = JSON.parse(credentialValue);
    return (
      typeof data === "object" &&
      data !== null &&
      (data as ServiceAccountKey).type === "service_account" &&
      typeof (data as ServiceAccountKey).private_key === "string" &&
      typeof (data as ServiceAccountKey).client_email === "string"
    );
  } catch {
    return false;
  }
}

/** Best-effort in-isolate cache: (service + scopes + key digest) → minted token. */
const tokenCache = new Map<string, MintedToken>();

/** Strip the PEM armor and decode the base64 body of a PKCS#8 private key. */
function pemToPkcs8(pem: string): Uint8Array {
  const b64 = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\s+/g, "");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * Mint a short-lived GCP access token from an SA JSON key. Builds an RS256 JWT
 * assertion (signed with the SA private key via WebCrypto) and exchanges it at
 * the token endpoint for a Bearer token (~1h).
 */
export async function mintGcpAccessToken(
  credentialValue: string,
  service: string,
  scopes?: string[],
): Promise<MintedToken> {
  const wantScopes = scopes && scopes.length > 0 ? scopes : DEFAULT_SCOPES;
  // The key material's digest is part of the key, so replacing the service
  // account key (rotation) can never be answered with a token minted from the
  // old one. Only the SHA-256 is kept, never the key.
  const cacheKey = `${service}\u0000${[...wantScopes].sort().join(" ")}\u0000${await sha256Hex(credentialValue)}`;

  const cached = tokenCache.get(cacheKey);
  // Re-mint 10 min before expiry, mirroring the reference's 50-min TTL.
  if (cached && cached.expiryTime - Date.now() > 10 * 60_000) return cached;

  const sa = JSON.parse(credentialValue) as ServiceAccountKey;
  if (!sa.private_key || !sa.client_email) {
    throw gcpMintFailed("Service account key is missing private_key/client_email");
  }
  const tokenUri = sa.token_uri || GOOGLE_TOKEN_URI;

  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + 3600;
  const header = base64UrlEncodeNoPad(utf8(JSON.stringify({ alg: "RS256", typ: "JWT" })));
  const claims = base64UrlEncodeNoPad(
    utf8(
      JSON.stringify({
        iss: sa.client_email,
        scope: wantScopes.join(" "),
        aud: tokenUri,
        iat,
        exp,
      }),
    ),
  );
  const signingInput = `${header}.${claims}`;

  const keyData = pemToPkcs8(sa.private_key);
  const cryptoKey = await crypto.subtle.importKey(
    "pkcs8",
    keyData as Uint8Array<ArrayBuffer>,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sigBuf = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", cryptoKey, utf8(signingInput));
  const assertion = `${signingInput}.${base64UrlEncodeNoPad(new Uint8Array(sigBuf))}`;

  const resp = await fetch(tokenUri, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: JWT_BEARER_GRANT, assertion }),
    redirect: "error", // the signed assertion must not follow a redirect
    signal: AbortSignal.timeout(TOKEN_ENDPOINT_TIMEOUT_MS),
  }).catch((e: unknown) => {
    throw gcpMintFailed(
      e instanceof DOMException && e.name === "TimeoutError"
        ? "Token endpoint timed out"
        : "Token endpoint request failed",
    );
  });
  if (!resp.ok) {
    throw gcpMintFailed(`Token endpoint returned ${resp.status}`);
  }
  const data = (await resp.json()) as { access_token?: string; expires_in?: number };
  if (!data.access_token) throw gcpMintFailed("Token endpoint returned no access_token");

  const expiresIn = typeof data.expires_in === "number" ? data.expires_in : 3600;
  const expiryTime = Date.now() + expiresIn * 1000;
  const minted: MintedToken = {
    accessToken: data.access_token,
    expiresAt: new Date(expiryTime).toISOString(),
    expiryTime,
    tokenType: "Bearer",
    serviceAccount: sa.client_email,
  };
  tokenCache.set(cacheKey, minted);
  return minted;
}

const gcpInterceptor: CredentialInterceptor = {
  name: "gcp-sa",
  matches(token) {
    return typeof token.accessToken === "string" && isGcpServiceAccount(token.accessToken);
  },
  async transform({ token, service }: InterceptorInput) {
    const raw = String(token.accessToken);
    // Always use DEFAULT_SCOPES — ignore any agent-supplied ?scopes= param so
    // an agent cannot widen the GCP scopes beyond what the operator approved.
    const minted = await mintGcpAccessToken(raw, service);
    return {
      accessToken: minted.accessToken,
      tokenType: minted.tokenType,
      expiresAt: minted.expiresAt,
      serviceName: service,
      serviceAccount: minted.serviceAccount,
      gcpMinted: true,
    };
  },
};

/** Transparent interceptor — contributes no capability of its own. */
export function gcpSaModule(): FeatureModule {
  return { name: "gcp-sa", interceptor: gcpInterceptor };
}
