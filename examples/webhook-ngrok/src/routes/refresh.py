import time
from datetime import datetime, timezone

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from auth import extract_auth_headers, verify_hmac
from config import OAUTH_TIMEOUT, error_response, http_client, log
from crypto import (
    build_encrypted_token_document,
    decrypt_token_field,
    encrypt,
    get_encryption_key,
)
from middleware import safe_json_loads
from store import kv_store, _mark_kv_dirty

router = APIRouter()


# ── TV-Mediated Refresh (/v1/refresh) ────────────────────────────────────────
#
# THIS IS THE ONLY ENDPOINT WHERE TOKEN VAULT RECEIVES CREDENTIAL MATERIAL.
#
# Two-phase flow:
#   Phase 1 (action: "get"):  TV asks for the decrypted refresh token
#   Phase 2 (action: "update"): TV sends new tokens after OAuth refresh
#
# All other endpoints remain zero-knowledge. The webhook acts as a
# killswitch: remove it and TV cannot access any credentials.
# ──────────────────────────────────────────────────────────────────────────────


@router.post("/v1/refresh")
async def tv_mediated_refresh(request: Request):
    """TV-mediated token refresh (two-phase).

    This is the ONLY endpoint where Token Vault receives credential
    material from the webhook. TV uses this for its built-in OAuth
    providers (Google, GitHub) where TV owns the client_secret.

    Phase 1 (action: "get"): Returns the decrypted refresh token.
    Phase 2 (action: "update"): Accepts new tokens, encrypts, and stores.
    """
    rid, body_bytes, sig, ts, req_id = extract_auth_headers(request)
    log.info("refresh_enter rid=%s", rid)

    if body_bytes is None:
        body_bytes = await request.body()

    auth_err = verify_hmac(body_bytes, sig, ts, req_id, rid)
    if auth_err is not None:
        return auth_err

    data, err = safe_json_loads(body_bytes)
    if data is None:
        return error_response(400, "invalid_request", f"Invalid JSON: {err}")

    request_id = data.get("requestId", req_id or rid)
    action = data.get("action", "")
    service = data.get("service", "")

    if not service:
        return error_response(400, "invalid_request", "Missing 'service'")

    if action == "get":
        return _handle_refresh_get(service, request_id, rid)
    elif action == "update":
        tokens = data.get("tokens", {})
        return _handle_refresh_update(service, tokens, request_id, rid)
    else:
        return error_response(400, "invalid_request", f"Unknown action: '{action}'. Must be 'get' or 'update'.")


def _handle_refresh_get(service: str, request_id: str, rid: str) -> JSONResponse:
    """Phase 1: Return the decrypted refresh token to TV."""
    stored_doc = kv_store["tokens"].get(service)
    if not stored_doc:
        log.warning("refresh_get_no_token rid=%s service=%s", rid, service)
        return JSONResponse(content={
            "requestId": request_id,
            "status": "no_token",
            "message": f"No token stored for service '{service}'",
        })

    key = get_encryption_key()
    try:
        if "fields" in stored_doc:
            refresh_token = decrypt_token_field(key, stored_doc, "refreshToken", rid)
        else:
            refresh_token = stored_doc.get("refreshToken")

        if not refresh_token:
            log.warning("refresh_get_no_refresh_token rid=%s service=%s", rid, service)
            return JSONResponse(content={
                "requestId": request_id,
                "status": "no_refresh_token",
                "message": f"No refresh token found for service '{service}'",
            })

        meta = stored_doc.get("meta", {})
        if not isinstance(meta, dict):
            meta = {}

        log.info("refresh_get_ok rid=%s service=%s", rid, service)
        return JSONResponse(content={
            "requestId": request_id,
            "status": "ok",
            "refreshToken": refresh_token,
            "meta": meta,
        })

    except Exception as e:
        log.exception("refresh_get_failed rid=%s", rid)
        return JSONResponse(
            status_code=500,
            content={
                "requestId": request_id,
                "status": "error",
                "message": f"Failed to decrypt refresh token: {e}",
            },
        )


def _handle_refresh_update(service: str, tokens: dict, request_id: str, rid: str) -> JSONResponse:
    """Phase 2: Encrypt and store new tokens from TV."""
    if not tokens:
        return error_response(400, "invalid_request", "Missing 'tokens' object")

    stored_doc = kv_store["tokens"].get(service)
    if not stored_doc:
        log.warning("refresh_update_no_token rid=%s service=%s", rid, service)
        return JSONResponse(content={
            "requestId": request_id,
            "status": "no_token",
            "message": f"No existing token to update for service '{service}'",
        })

    key = get_encryption_key()
    try:
        # Preserve existing metadata, update with new values
        existing_meta = stored_doc.get("meta", {})
        if not isinstance(existing_meta, dict):
            existing_meta = {}

        new_access = tokens.get("accessToken")
        new_refresh = tokens.get("refreshToken")
        expiry_time = tokens.get("expiryTime")

        updated_meta = dict(existing_meta)
        updated_meta["updatedAt"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if expiry_time:
            updated_meta["expiryTime"] = expiry_time
        updated_meta["hasRefreshToken"] = new_refresh is not None and len(str(new_refresh)) > 0

        encrypted_doc = build_encrypted_token_document(
            key, new_access, new_refresh, updated_meta, rid,
        )
        kv_store["tokens"][service] = encrypted_doc
        _mark_kv_dirty()

        new_expires_at = ""
        if expiry_time:
            new_expires_at = datetime.fromtimestamp(
                expiry_time / 1000, tz=timezone.utc
            ).isoformat()

        log.info("refresh_update_ok rid=%s service=%s", rid, service)
        return JSONResponse(content={
            "requestId": request_id,
            "status": "updated",
            "newExpiresAt": new_expires_at,
        })

    except Exception as e:
        log.exception("refresh_update_failed rid=%s", rid)
        return JSONResponse(
            status_code=500,
            content={
                "requestId": request_id,
                "status": "error",
                "message": f"Failed to store refreshed tokens: {e}",
            },
        )


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

            oauth_resp = await http_client.post(token_url, data=form_data, headers=headers, timeout=OAUTH_TIMEOUT)

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
            # No provider info, just acknowledge (webhook can refresh on its own)
            log.info("refresh_notify_ack_only rid=%s service=%s, no provider info", rid, service)
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
        _mark_kv_dirty()

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
