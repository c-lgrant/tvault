// Local E2E smoke client for the Node runtime (Phase 6). Drives a real HTTP
// round-trip against a running server: exchange → storage set → credential
// (with a signed ticket) → proxy (HMAC + proxy ticket, upstream looped back to
// /v1/health). Exits non-zero on the first failed assertion.
//
// Run via test/smoke/run.sh, which starts the server with throwaway key/store
// paths first.

import { base64Decode, type Bytes, utf8 } from "../../src/core/crypto/encoding.ts";
import { computeRequestSignature } from "../../src/core/protocol/hmac.ts";
import { signTicket } from "../../src/core/protocol/tickets.ts";
import type { TicketPayload } from "../../src/core/protocol/types.ts";

const PORT = process.env.PORT ?? "8799";
const BASE = `http://127.0.0.1:${PORT}`;
const ALLOWED_IP = "8.8.8.8"; // not the TV IP, so the denylist lets it through

let reqCounter = 0;
function nextRequestId(): string {
  reqCounter += 1;
  return `smoke_req_${reqCounter}`;
}
function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}
function nonce(): string {
  return crypto.randomUUID().replace(/-/g, "");
}

function assert(cond: boolean, msg: string): void {
  if (!cond) throw new Error(`ASSERT FAILED: ${msg}`);
  console.log(`  ✓ ${msg}`);
}

/** Signed HMAC POST mirroring how TV calls the webhook (requestId folded in). */
async function signedPost(secret: Bytes, path: string, payload: Record<string, unknown>): Promise<Response> {
  const requestId = nextRequestId();
  const body = JSON.stringify({ ...payload, requestId });
  const ts = String(nowSec());
  const sig = await computeRequestSignature(secret, ts, utf8(body));
  return fetch(`${BASE}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "X-TokenVault-Signature": `sha256=${sig}`,
      "X-TokenVault-Timestamp": ts,
      "X-TokenVault-Request-Id": requestId,
    },
    body,
  });
}

function ticket(secret: Bytes, overrides: Partial<TicketPayload>): Promise<string> {
  const payload: TicketPayload = {
    sub: "user_smoke",
    svc: "github",
    pur: "agent_credential",
    iat: nowSec(),
    exp: nowSec() + 300,
    nonce: nonce(),
    ...overrides,
  };
  return signTicket(secret, payload);
}

async function main(): Promise<void> {
  // ── Health (GET + HEAD, unauthenticated) ────────────────────────────────
  console.log("health:");
  const health = await fetch(`${BASE}/v1/health`);
  const healthJson = (await health.json()) as { status: string; capabilities: string[] };
  assert(health.status === 200, "GET /v1/health → 200");
  assert(healthJson.status === "healthy", "health reports healthy");
  assert(
    JSON.stringify(healthJson.capabilities) ===
      JSON.stringify(["store", "credential", "proxy", "refresh", "tv-refresh", "storage", "totp"]),
    `capabilities are canonical (${healthJson.capabilities.join(",")})`,
  );
  const head = await fetch(`${BASE}/v1/health`, { method: "HEAD" });
  assert(head.status === 200, "HEAD /v1/health → 200");

  // ── Exchange (obtain the HMAC secret) ───────────────────────────────────
  console.log("exchange:");
  const regResp = await fetch(`${BASE}/v1/register-url`);
  const reg = (await regResp.json()) as { code: string };
  assert(typeof reg.code === "string" && reg.code.length > 0, "register-url issued a code");
  const exResp = await fetch(`${BASE}/v1/exchange`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ code: reg.code }),
  });
  const ex = (await exResp.json()) as { hmacSecret: string; capabilities: string[] };
  assert(exResp.status === 200, "POST /v1/exchange → 200");
  assert(
    JSON.stringify(ex.capabilities) === JSON.stringify(healthJson.capabilities),
    "exchange capabilities match health",
  );
  const secret = base64Decode(ex.hmacSecret);

  // ── Storage set (HMAC) — store a credential the way the TV backend does ──
  console.log("storage set:");
  const setResp = await signedPost(secret, "/v1/storage", {
    operation: "set",
    collection: "tokens",
    key: "github",
    data: { accessToken: "ghp_smoketoken", refreshToken: "r_smoke", serviceName: "github", tokenType: "oauth" },
  });
  const setJson = (await setResp.json()) as { status: string };
  assert(setResp.status === 200 && setJson.status === "ok", "set tokens/github → ok");

  // list must not leak the access token
  const listResp = await signedPost(secret, "/v1/storage", { operation: "list", collection: "tokens" });
  const listJson = (await listResp.json()) as { items: Array<{ key: string; meta: Record<string, unknown> }> };
  assert(listJson.items.some((i) => i.key === "github"), "list includes github");
  assert(
    listJson.items.every((i) => !("accessToken" in i.meta)),
    "list never exposes accessToken",
  );

  // ── Credential (ticket auth) ────────────────────────────────────────────
  console.log("credential:");
  const credTicket = await ticket(secret, { pur: "agent_credential", svc: "github" });
  const credResp = await fetch(
    `${BASE}/v1/credential?ticket=${encodeURIComponent(credTicket)}&service=github`,
    { headers: { "x-forwarded-for": ALLOWED_IP } },
  );
  const credJson = (await credResp.json()) as { token: { accessToken: string } };
  assert(credResp.status === 200, "GET /v1/credential → 200");
  assert(credJson.token.accessToken === "ghp_smoketoken", "credential returns the stored access token");

  // ── Proxy (HMAC + proxy ticket; upstream looped back to /v1/health) ──────
  console.log("proxy:");
  const proxyTicket = await ticket(secret, { pur: "proxy", svc: "github" });
  const proxyResp = await signedPost(secret, "/v1/proxy", {
    ticket: proxyTicket,
    service: "github",
    upstream: { url: `${BASE}/v1/health`, method: "GET" },
    headerTemplates: { Authorization: "Bearer ${TOKEN}" },
  });
  const proxyText = await proxyResp.text();
  assert(proxyResp.status === 200, "POST /v1/proxy → 200");
  assert(proxyResp.headers.get("x-upstream-status") === "200", "proxy sets X-Upstream-Status: 200");
  assert(proxyText.includes("healthy"), "proxy streamed the upstream body back");

  console.log("\nALL SMOKE CHECKS PASSED");
}

main().catch((err) => {
  console.error(`\n${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
