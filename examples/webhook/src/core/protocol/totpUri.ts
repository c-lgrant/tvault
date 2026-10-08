// otpauth:// URI handling. A TOTP link carries the seed, so it is SENSITIVE:
// the webhook parses it into an encrypted `totpSecret` plus non-sensitive meta
// descriptors and never stores, returns or logs the URI itself.

import { invalidRequest } from "./errors.ts";

export interface ParsedTotpUri {
  /** Normalised base32 seed (upper-case, no spaces or padding). */
  secret: string;
  issuer?: string;
  accountName?: string;
  algorithm: "SHA1" | "SHA256" | "SHA512";
  digits: number;
  period: number;
}

const ALGORITHMS = new Set(["SHA1", "SHA256", "SHA512"]);

/**
 * Parse an otpauth://totp/... URI. Throws a 400 invalid_request WebhookError on
 * any malformed input. Error messages never echo the URI or the seed.
 */
export function parseTotpUri(uri: string): ParsedTotpUri {
  let url: URL;
  try {
    url = new URL(uri.trim());
  } catch {
    throw invalidRequest("Malformed totpUri");
  }
  if (url.protocol !== "otpauth:" || url.hostname.toLowerCase() !== "totp") {
    throw invalidRequest("totpUri must be an otpauth://totp/ link");
  }

  const secret = (url.searchParams.get("secret") ?? "")
    .replace(/\s+/g, "")
    .replace(/=+$/, "")
    .toUpperCase();
  if (!secret || !/^[A-Z2-7]+$/.test(secret)) {
    throw invalidRequest("totpUri has a missing or invalid secret");
  }

  let label: string;
  try {
    label = decodeURIComponent(url.pathname.replace(/^\/+/, ""));
  } catch {
    throw invalidRequest("Malformed totpUri");
  }
  let labelIssuer: string | undefined;
  let accountName: string | undefined;
  const colon = label.indexOf(":");
  if (colon >= 0) {
    labelIssuer = label.slice(0, colon).trim() || undefined;
    accountName = label.slice(colon + 1).trim() || undefined;
  } else {
    accountName = label.trim() || undefined;
  }
  const issuer = url.searchParams.get("issuer")?.trim() || labelIssuer;

  const algorithm = (url.searchParams.get("algorithm") ?? "SHA1").toUpperCase();
  if (!ALGORITHMS.has(algorithm)) throw invalidRequest("totpUri has an unsupported algorithm");

  const digitsRaw = url.searchParams.get("digits");
  const digits = digitsRaw == null ? 6 : Number(digitsRaw);
  if (!Number.isInteger(digits) || digits < 6 || digits > 8) {
    throw invalidRequest("totpUri has invalid digits");
  }

  const periodRaw = url.searchParams.get("period");
  const period = periodRaw == null ? 30 : Number(periodRaw);
  if (!Number.isInteger(period) || period < 1 || period > 3600) {
    throw invalidRequest("totpUri has an invalid period");
  }

  return {
    secret,
    ...(issuer ? { issuer } : {}),
    ...(accountName ? { accountName } : {}),
    algorithm: algorithm as ParsedTotpUri["algorithm"],
    digits,
    period,
  };
}

/** The meta descriptor fields derived from a parsed URI (never the secret). */
export function totpDescriptors(p: ParsedTotpUri): Record<string, unknown> {
  return {
    ...(p.issuer ? { totpIssuer: p.issuer } : {}),
    ...(p.accountName ? { totpAccountName: p.accountName } : {}),
    totpAlgorithm: p.algorithm,
    totpDigits: p.digits,
    totpPeriod: p.period,
  };
}
