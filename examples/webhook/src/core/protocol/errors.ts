// Spec-compliant error envelope: { "error": <code>, "message": <text> } with an
// HTTP status. Mirrors config.error_response() in the Python reference.

export interface ErrorBody {
  error: string;
  message: string;
}

/**
 * A protocol error carrying the HTTP status, machine-readable code, and a human
 * message. Handlers/middleware can `throw` it; the app's error boundary (or a
 * caller) turns it into a `{error, message}` JSON response via `toBody()`.
 */
export class WebhookError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "WebhookError";
    this.status = status;
    this.code = code;
  }

  toBody(): ErrorBody {
    return { error: this.code, message: this.message };
  }
}

// ── Common errors, named to match the reference's error codes ────────────────

export const setupRequired = () =>
  new WebhookError(403, "setup_required", "Webhook not configured.");

export const authFailed = (message: string) =>
  new WebhookError(401, "auth_failed", message);

export const invalidRequest = (message: string) =>
  new WebhookError(400, "invalid_request", message);

export const ticketInvalid = (message: string) =>
  new WebhookError(401, "ticket_invalid", message);

export const ticketExpired = (message: string) =>
  new WebhookError(401, "ticket_expired", message);

export const tokenNotFound = (message: string) =>
  new WebhookError(404, "token_not_found", message);

export const forbidden = (message: string) =>
  new WebhookError(403, "forbidden", message);

export const internalError = (message: string) =>
  new WebhookError(500, "internal_error", message);

// ── Proxy upstream + interceptor failures ────────────────────────────────────

export const upstreamTimeout = (message: string) =>
  new WebhookError(504, "upstream_timeout", message);

export const upstreamError = (message: string) =>
  new WebhookError(502, "upstream_error", message);

export const gcpMintFailed = (message: string) =>
  new WebhookError(500, "gcp_mint_failed", message);

export const totpFailed = (message: string) =>
  new WebhookError(500, "totp_failed", message);

export const notTotp = (message: string) =>
  new WebhookError(400, "not_totp", message);
