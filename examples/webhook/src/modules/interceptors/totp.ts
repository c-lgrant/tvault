// TOTP interceptor + /v1/totp-code endpoint (routes/totp.py, direct_access.py:231-256).
// A stored TOTP secret never leaves the webhook: the credential path returns a
// freshly-generated one-time code in place of the secret, and the dedicated
// endpoint serves browser reveal. RFC 6238 is implemented with WebCrypto HMAC
// (SHA-1/256/512) — no pyotp dependency, so it runs on Node and Workers alike.

import { corsHeaders, preflightResponse } from "../../core/middleware/cors.ts";
import { denylist } from "../../core/middleware/denylist.ts";
import { readJsonBody } from "../../core/middleware/body.ts";
import { sendError } from "../../core/middleware/respond.ts";
import {
  invalidRequest,
  notTotp,
  setupRequired,
  ticketInvalid,
  tokenNotFound,
  totpFailed,
} from "../../core/protocol/errors.ts";
import { verifyTicket } from "../../core/protocol/tickets.ts";
import { readTokenObject } from "../../core/protocol/tokendoc.ts";
import type { CredentialInterceptor, FeatureModule, InterceptorInput } from "../../core/registry.ts";

// /v1/totp-code accepts the credential purposes plus a dedicated totp_code one.
const TOTP_PURPOSES = new Set(["agent_credential", "user_reveal", "browser_credential", "totp_code"]);

const DIGEST_BY_ALGORITHM: Record<string, "SHA-1" | "SHA-256" | "SHA-512"> = {
  SHA1: "SHA-1",
  SHA256: "SHA-256",
  SHA512: "SHA-512",
};

interface TotpResult {
  code: string;
  remainingSeconds: number;
  period: number;
  digits: number;
}

/** Decode an RFC 4648 base32 secret (upper-case, no padding required). */
function base32Decode(secret: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = secret.replace(/=+$/, "").replace(/\s+/g, "").toUpperCase();
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = alphabet.indexOf(ch);
    if (idx === -1) throw totpFailed("TOTP secret is not valid base32");
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}

function readNumber(token: Record<string, unknown>, meta: Record<string, unknown>, field: string, fallback: number): number {
  const v = token[field] ?? meta[field];
  const n = typeof v === "number" ? v : typeof v === "string" ? Number(v) : NaN;
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

/** Generate the current TOTP code from a decrypted secret (totp.py:27-48). */
export async function generateTotpCode(
  secret: string,
  token: Record<string, unknown>,
  meta: Record<string, unknown>,
  nowMs: number = Date.now(),
): Promise<TotpResult> {
  const algorithm = String(token.totpAlgorithm ?? meta.totpAlgorithm ?? "SHA1").toUpperCase();
  const digest = DIGEST_BY_ALGORITHM[algorithm] ?? "SHA-1";
  const digits = readNumber(token, meta, "totpDigits", 6);
  const period = readNumber(token, meta, "totpPeriod", 30);

  const nowSeconds = Math.floor(nowMs / 1000);
  const counter = Math.floor(nowSeconds / period);
  const counterBytes = new Uint8Array(8);
  // 64-bit big-endian counter; the low 53 bits are all JS can represent exactly.
  let c = counter;
  for (let i = 7; i >= 0; i--) {
    counterBytes[i] = c & 0xff;
    c = Math.floor(c / 256);
  }

  const key = await crypto.subtle.importKey(
    "raw",
    base32Decode(secret) as Uint8Array<ArrayBuffer>,
    { name: "HMAC", hash: digest },
    false,
    ["sign"],
  );
  const hs = new Uint8Array(await crypto.subtle.sign("HMAC", key, counterBytes as Uint8Array<ArrayBuffer>));

  // Dynamic truncation (RFC 4226 §5.3).
  const offset = hs[hs.length - 1]! & 0x0f;
  const binary =
    ((hs[offset]! & 0x7f) << 24) |
    ((hs[offset + 1]! & 0xff) << 16) |
    ((hs[offset + 2]! & 0xff) << 8) |
    (hs[offset + 3]! & 0xff);
  const code = (binary % 10 ** digits).toString().padStart(digits, "0");
  const remainingSeconds = period - (nowSeconds % period);

  return { code, remainingSeconds, period, digits };
}

const totpInterceptor: CredentialInterceptor = {
  name: "totp",
  matches(token) {
    return token.tokenType === "TOTP" && typeof token.totpSecret === "string" && token.totpSecret.length > 0;
  },
  async transform({ token, service, storedDoc }: InterceptorInput) {
    const meta = (storedDoc.meta ?? {}) as Record<string, unknown>;
    const result = await generateTotpCode(String(token.totpSecret), token, meta);
    return {
      accessToken: result.code,
      tokenType: "TOTP",
      serviceName: service,
      remainingSeconds: result.remainingSeconds,
      period: result.period,
      digits: result.digits,
      totpGenerated: true,
    };
  },
};

/** Contributes the "totp" capability, the credential interceptor, and the endpoint. */
export function totpModule(): FeatureModule {
  return {
    name: "totp",
    capability: "totp",
    interceptor: totpInterceptor,
    register(app, ctx) {
      app.options("/v1/totp-code", (c) => preflightResponse(c));

      app.on(["GET", "POST"], "/v1/totp-code", denylist(ctx.config), async (c) => {
        const cors = corsHeaders(c.req.header("origin"));
        try {
          if (!(await ctx.secrets.isConfigured())) return sendError(c, setupRequired(), cors);

          let ticket = "";
          let service = "";
          if (c.req.method === "GET") {
            const params = new URL(c.req.url).searchParams;
            ticket = params.get("ticket") ?? "";
            service = params.get("service") ?? "";
          } else {
            const body = readJsonBody(c);
            ticket = typeof body.ticket === "string" ? body.ticket : "";
            service = typeof body.service === "string" ? body.service : "";
          }

          if (!ticket) return sendError(c, invalidRequest("Missing 'ticket' parameter"), cors);
          if (!service) return sendError(c, invalidRequest("Missing 'service' parameter"), cors);

          const secret = await ctx.secrets.hmacSecret();
          const payload = await verifyTicket(ticket, secret, ctx.replay);

          if (!TOTP_PURPOSES.has(payload.pur)) {
            return sendError(c, ticketInvalid(`Invalid ticket purpose: '${payload.pur}'`), cors);
          }
          if (payload.svc !== service) {
            return sendError(c, ticketInvalid(`Ticket is for service '${payload.svc}', not '${service}'`), cors);
          }

          const storedDoc = await ctx.storage.get("tokens", service);
          if (!storedDoc) return sendError(c, tokenNotFound(`No token stored for service '${service}'`), cors);

          const meta = (storedDoc.meta ?? {}) as Record<string, unknown>;
          const tokenType = meta.tokenType ?? (storedDoc as Record<string, unknown>).tokenType ?? "";
          if (tokenType !== "TOTP") {
            return sendError(c, notTotp(`Token '${service}' is not a TOTP token (type: ${String(tokenType)})`), cors);
          }

          const key = await ctx.secrets.encryptionKey();
          const token = await readTokenObject(key, storedDoc);
          const totpSecret = token.totpSecret;
          if (typeof totpSecret !== "string" || !totpSecret) {
            return sendError(c, invalidRequest("TOTP secret is missing from stored token"), cors);
          }

          const result = await generateTotpCode(totpSecret, token, meta);
          return c.json(result, 200, cors);
        } catch (e) {
          return sendError(c, e, cors);
        }
      });
    },
  };
}
