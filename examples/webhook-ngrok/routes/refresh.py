import time
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from auth import extract_auth_headers, verify_hmac
from config import OAUTH_TIMEOUT, error_response, log
from crypto import (
    build_encrypted_token_document,
    decrypt_token_field,
    get_encryption_key,
)
from middleware import safe_json_loads
from store import kv_store, save_kv_store

router = APIRouter()


@router.post("/v1/refresh-notify")
async def refresh_notify(request: Request):
    """Handle refresh notifications from TV.

    TV notifies the webhook when a token needs refresh. The webhook
    owns the credential and handles the actual OAuth refresh.
    """
    rid, body_bytes, sig, ts, req_id = extract_auth_headers(request)
    log.info("refresh_notify_enter rid=%s", rid)

    if body_bytes is None:
        body_bytes = await request.body()

    auth_err = verify_hmac(body_bytes, sig, ts, req_id, rid)
    if auth_err is not None:
        return auth_err

    data, err = safe_json_loads(body_bytes)
    if data is None:
        return error_response(400, "invalid_request", f"Invalid JSON: {err}")

    request_id = data.get("requestId", req_id or rid)
    service = data.get("service", "")
    reason = data.get("reason", "token_expiring")
    refresh_hint = data.get("refreshHint", {})

    if not service:
        return error_response(400, "invalid_request", "Missing 'service'")

    log.info("refresh_notify rid=%s service=%s reason=%s", rid, service, reason)

    # Get stored token
    stored_doc = kv_store["tokens"].get(service)
    if not stored_doc:
        return JSONResponse(content={
            "requestId": request_id,
            "status": "no_token",
            "message": f"No token stored for service '{service}'",
        })

    # Decrypt refresh token (or read plaintext)
    key = get_encryption_key()
    try:
        if "fields" in stored_doc:
            refresh_token = decrypt_token_field(key, stored_doc, "refreshToken", rid)
        else:
            refresh_token = stored_doc.get("refreshToken")
        if not refresh_token:
            return JSONResponse(content={
                "requestId": request_id,
                "status": "no_refresh_token",
                "message": f"No refreshToken found for service '{service}'",
            })

        existing_meta = stored_doc.get("meta", {})

        # Call OAuth provider's token endpoint
        token_url = refresh_hint.get("tokenUrl")
        client_id = refresh_hint.get("clientId")
        client_secret = refresh_hint.get("clientSecret")

        if token_url and client_id and client_secret:
            form_data = {
                "grant_type": "refresh_token",
                "client_id": client_id,
                "client_secret": client_secret,
                "refresh_token": refresh_token,
            }
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            provider_name = refresh_hint.get("provider", "").lower()
            if provider_name == "github":
                headers["Accept"] = "application/json"

            log.info("refresh_oauth_call rid=%s token_url=%s provider=%s", rid, token_url, provider_name)

            async with httpx.AsyncClient(timeout=OAUTH_TIMEOUT) as client:
                oauth_resp = await client.post(token_url, data=form_data, headers=headers)

            if oauth_resp.status_code >= 400:
                log.warning("refresh_oauth_error rid=%s status=%s", rid, oauth_resp.status_code)
                return JSONResponse(content={
                    "requestId": request_id,
                    "status": "refresh_failed",
                    "message": f"OAuth provider returned {oauth_resp.status_code}",
                })

            oauth_data = oauth_resp.json()
            new_access_token = oauth_data.get("access_token", "")
            new_refresh_token = oauth_data.get("refresh_token", refresh_token)
            expires_in = oauth_data.get("expires_in", 3600)
        else:
            # No provider info — just acknowledge (webhook can refresh on its own)
            log.info("refresh_notify_ack_only rid=%s service=%s — no provider info", rid, service)
            return JSONResponse(content={
                "requestId": request_id,
                "status": "acknowledged",
                "message": "Notification received but no provider info for auto-refresh",
            })

        # Build updated meta
        expiry_ms = int((time.time() + expires_in) * 1000)
        updated_meta = {
            "serviceName": service,
            "tokenType": existing_meta.get("tokenType", refresh_hint.get("provider", "oauth")),
            "expiryTime": expiry_ms,
            "updatedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        if "createdAt" in existing_meta:
            updated_meta["createdAt"] = existing_meta["createdAt"]

        # Encrypt and store the new tokens
        encrypted_doc = build_encrypted_token_document(
            key, new_access_token, new_refresh_token, updated_meta, rid,
        )
        kv_store["tokens"][service] = encrypted_doc
        save_kv_store()

        log.info("refresh_notify_exit rid=%s service=%s status=refreshed", rid, service)
        return JSONResponse(content={
            "requestId": request_id,
            "status": "refreshed",
            "newExpiresAt": datetime.fromtimestamp(expiry_ms / 1000, tz=timezone.utc).isoformat(),
        })

    except Exception as e:
        log.exception("refresh_notify_failed rid=%s", rid)
        return JSONResponse(
            status_code=500,
            content={
                "requestId": request_id,
                "status": "error",
                "message": f"Refresh failed: {e}",
            },
        )
