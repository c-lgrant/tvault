// CORS for the browser-facing endpoints (store + credential). The credential
// ticket's HMAC is the real security boundary — the reference notes this
// explicitly — so we reflect the requesting Origin rather than pinning one,
// which is exactly what the browser store/credential flows need.

import type { Context } from "hono";

export function corsHeaders(origin: string | undefined): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": origin || "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}

/** 204 preflight response carrying the reflected CORS headers. */
export function preflightResponse(c: Context): Response {
  return new Response(null, { status: 204, headers: corsHeaders(c.req.header("origin")) });
}
