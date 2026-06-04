// Turn a thrown value into a spec-compliant error response. Optional headers
// let browser-facing endpoints attach CORS to their errors.

import type { Context } from "hono";
import type { ContentfulStatusCode } from "hono/utils/http-status";
import { internalError, WebhookError } from "../protocol/errors.ts";

export function sendError(
  c: Context,
  e: unknown,
  headers: Record<string, string> = {},
): Response {
  const err =
    e instanceof WebhookError
      ? e
      : internalError(`Unexpected error: ${e instanceof Error ? e.message : String(e)}`);
  return c.json(err.toBody(), err.status as ContentfulStatusCode, headers);
}
