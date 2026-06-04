// Parse the captured raw body as a JSON object. Used by every endpoint that
// reads a body (it parses the exact bytes HMAC was verified over, never a
// framework re-read).

import type { Context } from "hono";
import { fromUtf8 } from "../crypto/encoding.ts";
import { invalidRequest } from "../protocol/errors.ts";
import type { AppEnv } from "../app.ts";

export function readJsonBody(c: Context<AppEnv>): Record<string, unknown> {
  const raw = c.get("rawBody");
  try {
    const parsed: unknown = JSON.parse(fromUtf8(raw));
    if (parsed === null || typeof parsed !== "object") throw new Error("body is not an object");
    return parsed as Record<string, unknown>;
  } catch (e) {
    throw invalidRequest(`Invalid JSON: ${e instanceof Error ? e.message : String(e)}`);
  }
}
