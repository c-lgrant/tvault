import base64
import time
import uuid
from typing import Optional

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from config import (
    CAPABILITIES,
    TOKENVAULT_FRONTEND_URL,
    WEBHOOK_EXTERNAL_URL,
    WEBHOOK_VERSION,
    error_response,
    log,
    registration_codes,
    start_time,
)
from middleware import safe_json_loads
from store import kv_store, save_store, store

router = APIRouter()


@router.get("/v1/register-url")
async def register_url(request: Request):
    """Generate a registration URL for binding this webhook to Token Vault.

    Returns a URL the user can click/paste into their browser to complete
    the webhook-bind flow. Contains a one-time code (5-minute TTL).
    """
    rid = getattr(request.state, "request_id", "unknown")
    log.info("register_url_enter rid=%s", rid)

    external_url = WEBHOOK_EXTERNAL_URL
    if not external_url:
        # Try to auto-detect from request
        host = request.headers.get("x-forwarded-host") or request.headers.get("host", "")
        proto = request.headers.get("x-forwarded-proto", "https")
        if host:
            external_url = f"{proto}://{host}"
        else:
            return error_response(
                500, "config_error",
                "WEBHOOK_EXTERNAL_URL not set and could not auto-detect. "
                "Set the WEBHOOK_EXTERNAL_URL environment variable.",
            )

    frontend_url = TOKENVAULT_FRONTEND_URL.rstrip("/")

    # Generate one-time code
    code = str(uuid.uuid4())
    registration_codes[code] = {
        "created_at": time.time(),
        "used": False,
    }

    # Build registration URL
    webhook_url_b64 = base64.b64encode(external_url.encode()).decode()
    hmac_hash = store["hmac_secret_hash"]

    reg_url = (
        f"{frontend_url}/vault/webhook-bind"
        f"?code={code}"
        f"&webhook_url={webhook_url_b64}"
        f"&hmac_hash={hmac_hash}"
    )

    log.info(
        "register_url_exit rid=%s code=%s external_url=%s",
        rid, code[:8] + "...", external_url,
    )

    return {
        "registrationUrl": reg_url,
        "code": code,
        "expiresIn": 300,
        "webhookUrl": external_url,
    }


@router.post("/v1/exchange")
async def exchange(request: Request):
    """Exchange a one-time code for the webhook's HMAC secret.

    Called by the TV backend during webhook-bind. The code itself is
    the authentication — no HMAC headers required (we don't have a
    shared secret yet).
    """
    rid = getattr(request.state, "request_id", "unknown")
    log.info("exchange_enter rid=%s", rid)

    body_bytes = getattr(request.state, "raw_body", None)
    if body_bytes is None:
        body_bytes = await request.body()

    data, err = safe_json_loads(body_bytes)
    if data is None:
        return error_response(400, "invalid_request", f"Invalid JSON: {err}")

    code = data.get("code", "")
    if not code:
        return error_response(400, "invalid_request", "Missing 'code'")

    # Look up the one-time code
    code_data = registration_codes.get(code)
    if code_data is None:
        log.warning("exchange_code_expired rid=%s code=%s", rid, code[:8] + "...")
        return error_response(410, "code_expired", "Registration code expired or not found")

    if code_data.get("used"):
        log.warning("exchange_code_reused rid=%s code=%s", rid, code[:8] + "...")
        return error_response(410, "code_used", "Registration code already used")

    # Mark code as used
    code_data["used"] = True

    # Store the origin from the request for CORS
    origin = request.headers.get("origin", "")
    if origin:
        store["tokenvault_origin"] = origin
        save_store(store)

    # Return the HMAC secret
    hmac_secret_b64 = base64.b64encode(store["hmac_secret"]).decode("ascii")

    resp = {
        "hmacSecret": hmac_secret_b64,
        "webhookId": store["webhook_id"],
        "version": WEBHOOK_VERSION,
        "capabilities": CAPABILITIES,
    }

    log.info("exchange_exit rid=%s webhook_id=%s", rid, store["webhook_id"])
    return resp


# ── Browser Bind Page ─────────────────────────────────────────────────────────

@router.get("/bind")
async def bind_page(request: Request, force: Optional[str] = None):
    """One-click browser page to bind this webhook to Token Vault."""
    rid = getattr(request.state, "request_id", "unknown")
    log.info("bind_page_enter rid=%s force=%s", rid, force)

    webhook_id = store.get("webhook_id", "unknown")
    origin = store.get("tokenvault_origin", "")
    has_tokens = len(kv_store.get("tokens", {})) > 0

    # Already bound? Show status page (unless ?force=1)
    if origin and has_tokens and force != "1":
        token_count = len(kv_store["tokens"])
        uptime = int(time.time() - start_time)
        return HTMLResponse(f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TokenVault Webhook — Connected</title>
<style>
  *{{margin:0;padding:0;box-sizing:border-box}}
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0a0a0a;color:#e5e5e5;display:flex;align-items:center;justify-content:center;min-height:100vh}}
  .card{{background:#171717;border:1px solid #262626;border-radius:12px;padding:2.5rem;max-width:460px;width:100%}}
  h1{{font-size:1.25rem;margin-bottom:.25rem}}
  .subtitle{{color:#a3a3a3;font-size:.875rem;margin-bottom:1.5rem}}
  .status{{display:flex;align-items:center;gap:.5rem;padding:.75rem 1rem;background:#052e16;border:1px solid #14532d;border-radius:8px;margin-bottom:1.5rem;font-size:.875rem;color:#4ade80}}
  .dot{{width:8px;height:8px;background:#4ade80;border-radius:50%;flex-shrink:0}}
  .info{{font-size:.8rem;color:#737373;margin-bottom:.5rem}}
  .info span{{color:#a3a3a3}}
  .rebind{{display:inline-block;margin-top:1.5rem;color:#737373;font-size:.8rem;text-decoration:underline;text-underline-offset:2px}}
  .rebind:hover{{color:#a3a3a3}}
</style></head><body>
<div class="card">
  <h1>Webhook Connected</h1>
  <p class="subtitle">This webhook is already bound to TokenVault.</p>
  <div class="status"><span class="dot"></span> Connected</div>
  <p class="info">Webhook ID: <span>{webhook_id[:8]}…</span></p>
  <p class="info">Origin: <span>{origin}</span></p>
  <p class="info">Tokens stored: <span>{token_count}</span></p>
  <p class="info">Uptime: <span>{uptime // 3600}h {(uptime % 3600) // 60}m</span></p>
  <a class="rebind" href="/bind?force=1">Re-bind to TokenVault</a>
</div></body></html>""")

    # Not bound — generate registration URL and show connect page
    external_url = WEBHOOK_EXTERNAL_URL
    if not external_url:
        host = request.headers.get("x-forwarded-host") or request.headers.get("host", "")
        proto = request.headers.get("x-forwarded-proto", "https")
        if host:
            external_url = f"{proto}://{host}"
        else:
            return HTMLResponse("""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TokenVault Webhook — Error</title>
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0a0a0a;color:#e5e5e5;display:flex;align-items:center;justify-content:center;min-height:100vh}
  .card{background:#171717;border:1px solid #262626;border-radius:12px;padding:2.5rem;max-width:460px;width:100%}
  h1{font-size:1.25rem;color:#f87171;margin-bottom:.5rem}
  p{color:#a3a3a3;font-size:.875rem}
  code{background:#262626;padding:.125rem .375rem;border-radius:4px;font-size:.8rem}
</style></head><body>
<div class="card">
  <h1>Configuration Error</h1>
  <p>Cannot detect external URL. Set the <code>WEBHOOK_EXTERNAL_URL</code> environment variable.</p>
</div></body></html>""", status_code=500)

    frontend_url = TOKENVAULT_FRONTEND_URL.rstrip("/")

    # Generate one-time code
    code = str(uuid.uuid4())
    registration_codes[code] = {"created_at": time.time(), "used": False}

    webhook_url_b64 = base64.b64encode(external_url.encode()).decode()
    hmac_hash = store["hmac_secret_hash"]
    reg_url = f"{frontend_url}/vault/webhook-bind?code={code}&webhook_url={webhook_url_b64}&hmac_hash={hmac_hash}"

    log.info("bind_page_exit rid=%s code=%s external_url=%s", rid, code[:8] + "...", external_url)

    return HTMLResponse(f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TokenVault Webhook — Connect</title>
<style>
  *{{margin:0;padding:0;box-sizing:border-box}}
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0a0a0a;color:#e5e5e5;display:flex;align-items:center;justify-content:center;min-height:100vh}}
  .card{{background:#171717;border:1px solid #262626;border-radius:12px;padding:2.5rem;max-width:460px;width:100%;text-align:center}}
  h1{{font-size:1.25rem;margin-bottom:.25rem}}
  .subtitle{{color:#a3a3a3;font-size:.875rem;margin-bottom:1.5rem}}
  .url-box{{background:#0a0a0a;border:1px solid #262626;border-radius:8px;padding:.75rem 1rem;margin-bottom:1.5rem;font-family:monospace;font-size:.75rem;color:#a3a3a3;word-break:break-all;text-align:left}}
  .btn{{display:inline-block;background:#2563eb;color:#fff;font-size:.9rem;font-weight:500;padding:.75rem 2rem;border-radius:8px;text-decoration:none;transition:background .15s}}
  .btn:hover{{background:#1d4ed8}}
  .info{{font-size:.75rem;color:#525252;margin-top:1rem}}
</style></head><body>
<div class="card">
  <h1>Connect to TokenVault</h1>
  <p class="subtitle">Bind this webhook to your TokenVault account.</p>
  <div class="url-box">{external_url}</div>
  <a class="btn" href="{reg_url}">Connect to TokenVault</a>
  <p class="info">Code expires in 5 minutes.</p>
</div></body></html>""")
