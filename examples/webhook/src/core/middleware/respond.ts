// Turn a thrown value into a spec-compliant error response. Optional headers
// let browser-facing endpoints attach CORS to their errors.
//
// Only a WebhookError's message is ever sent back: its text is written for the
// caller. Any other error can carry request data (a runtime error quoting a
// header value that held a credential), so the caller gets a fixed message and
// the log gets only the error's class name.

import type { Context } from "hono";
import type { ContentfulStatusCode } from "hono/utils/http-status";
import { internalError, WebhookError } from "../protocol/errors.ts";

export function sendError(
  c: Context,
  e: unknown,
  headers: Record<string, string> = {},
): Response {
  let err: WebhookError;
  if (e instanceof WebhookError) {
    err = e;
  } else {
    console.error(`[error] unexpected ${e instanceof Error ? e.name : typeof e}`);
    err = internalError("Internal error");
  }
  return c.json(err.toBody(), err.status as ContentfulStatusCode, headers);
}
