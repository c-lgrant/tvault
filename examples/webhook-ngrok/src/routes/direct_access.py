from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from auth import cors_headers, verify_ticket
from config import SENSITIVE_FIELDS, error_response, log, now_iso
from crypto import build_encrypted_token_document, decrypt, get_encryption_key
from gcp import is_gcp_service_account, mint_access_token
from middleware import safe_json_loads
from store import kv_store, save_kv_store

router = APIRouter()


def _cors_response(resp: Response, cors: dict) -> Response:
    for k, v in cors.items():
        resp.headers[k] = v
    return resp


# ── Token Storage (browser-direct) ───────────────────────────────────────────

@router.options("/v1/store")
async def store_preflight(request: Request):
    """CORS preflight for browser-direct token storage."""
    origin = request.headers.get("origin", "")
    return Response(status_code=204, headers=cors_headers(origin))


@router.post("/v1/store")
async def store_token(request: Request):
    """Store a token directly from the browser.

    The browser sends a ticket (signed by TV) plus the plaintext token data.
    The webhook verifies the ticket, encrypts the token with its own key,
    and stores it. TV never sees the plaintext credential.
    """
    rid = getattr(request.state, "request_id", "unknown")
    log.info("store_enter rid=%s", rid)
    request_origin = request.headers.get("origin", "")
    cors = cors_headers(request_origin)

    body_bytes = getattr(request.state, "raw_body", None)
    if body_bytes is None:
        body_bytes = await request.body()

    data, err = safe_json_loads(body_bytes)
    if data is None:
        return _cors_response(error_response(400, "invalid_request", f"Invalid JSON: {err}"), cors)

    ticket = data.get("ticket", "")
    service = data.get("service", "")
    token_data = data.get("tokenData", {})

    if not ticket:
        return _cors_response(error_response(400, "invalid_request", "Missing 'ticket'"), cors)

    if not service:
        return _cors_response(error_response(400, "invalid_request", "Missing 'service'"), cors)

    if not token_data:
        return _cors_response(error_response(400, "invalid_request", "Missing 'tokenData'"), cors)

    # Verify ticket
    payload, ticket_err = verify_ticket(ticket, rid)
    if ticket_err is not None:
        return _cors_response(ticket_err, cors)

    # Verify ticket purpose is "store"
    if payload.get("pur") != "store":
        log.warning("store_wrong_purpose rid=%s purpose=%s", rid, payload.get("pur"))
        return _cors_response(error_response(401, "ticket_invalid", "Ticket purpose must be 'store'"), cors)

    # Verify service matches ticket
    if payload.get("svc") != service:
        log.warning("store_service_mismatch rid=%s ticket=%s requested=%s", rid, payload.get("svc"), service)
        return _cors_response(error_response(401, "ticket_invalid", f"Ticket is for service '{payload.get('svc')}', not '{service}'"), cors)

    # Encrypt and store
    key = get_encryption_key()
    try:
        access_token = token_data.get("accessToken")
        refresh_token = token_data.get("refreshToken")

        # Build meta from ALL non-sensitive tokenData fields.
        # This ensures scope, expiryTime, permissions, cert/SSH metadata, etc.
        # are preserved for the list endpoint.
        meta = {}
        for k, v in token_data.items():
            if k not in SENSITIVE_FIELDS and v is not None:
                meta[k] = v

        # Ensure required fields
        meta["serviceName"] = service
        meta.setdefault("tokenType", "oauth")
        meta["createdAt"] = now_iso()
        meta["hasRefreshToken"] = refresh_token is not None and len(str(refresh_token)) > 0

        # Convert expiresAt (ISO string) to expiryTime (ms since epoch) if not already set
        if not meta.get("expiryTime") and token_data.get("expiresAt"):
            try:
                from datetime import datetime, timezone
                dt = datetime.fromisoformat(token_data["expiresAt"].replace("Z", "+00:00"))
                meta["expiryTime"] = int(dt.timestamp() * 1000)
            except (ValueError, AttributeError):
                pass

        # Collect additional sensitive fields (cert/SSH data)
        extra_sensitive = {}
        for sf in ("certificateData", "privateKeyData", "certificateChain", "sshPrivateKey"):
            val = token_data.get(sf)
            if val:
                extra_sensitive[sf] = val

        encrypted_doc = build_encrypted_token_document(
            key, access_token, refresh_token, meta, rid,
            extra_sensitive=extra_sensitive,
        )

        kv_store["tokens"][service] = encrypted_doc
        save_kv_store()

        log.info("store_exit rid=%s service=%s sub=%s", rid, service, payload.get("sub"))

        resp = JSONResponse(
            content={
                "status": "stored",
                "service": service,
                "meta": meta,
            },
            headers=cors,
        )
        return resp

    except Exception as e:
        log.exception("store_failed rid=%s", rid)
        return _cors_response(error_response(500, "internal_error", f"Token storage failed: {e}"), cors)


# ── Credential Retrieval (zero-knowledge) ────────────────────────────────────

@router.options("/v1/credential")
async def credential_preflight(request: Request):
    """CORS preflight for browser-based credential requests."""
    origin = request.headers.get("origin", "")
    return Response(status_code=204, headers=cors_headers(origin))


@router.post("/v1/credential")
@router.get("/v1/credential")
async def credential(request: Request):
    """Zero-knowledge credential access endpoint.

    Accepts either:
      - POST with JSON body: {"ticket": "...", "service": "..."}
      - GET with query params: ?ticket=...&service=... (from 307 redirect)

    Uses the webhook's own encryption key to decrypt.
    """
    rid = getattr(request.state, "request_id", "unknown")
    log.info("credential_enter rid=%s method=%s", rid, request.method)
    request_origin = request.headers.get("origin", "")
    cors = cors_headers(request_origin)

    # Extract ticket and service from request
    if request.method == "GET":
        ticket = request.query_params.get("ticket", "")
        service = request.query_params.get("service", "")
    else:
        body_bytes = getattr(request.state, "raw_body", None)
        if body_bytes is None:
            body_bytes = await request.body()
        data, err = safe_json_loads(body_bytes)
        if data is None:
            return _cors_response(error_response(400, "invalid_request", f"Invalid JSON: {err}"), cors)
        ticket = data.get("ticket", "")
        service = data.get("service", "")

    if not ticket:
        return _cors_response(error_response(400, "invalid_request", "Missing 'ticket' parameter"), cors)

    if not service:
        return _cors_response(error_response(400, "invalid_request", "Missing 'service' parameter"), cors)

    # Verify ticket
    payload, ticket_err = verify_ticket(ticket, rid)
    if ticket_err is not None:
        return _cors_response(ticket_err, cors)

    # Verify ticket purpose is valid for credential retrieval
    purpose = payload.get("pur")
    if purpose not in ("agent_credential", "user_reveal", "browser_credential"):
        log.warning("credential_invalid_purpose rid=%s purpose=%s", rid, purpose)
        return _cors_response(error_response(401, "ticket_invalid", f"Invalid ticket purpose for this endpoint: '{purpose}'"), cors)

    # Verify service matches ticket
    ticket_svc = payload.get("svc", "")
    if ticket_svc != service:
        log.warning("credential_service_mismatch rid=%s ticket_svc=%s requested=%s", rid, ticket_svc, service)
        return _cors_response(error_response(401, "ticket_invalid", f"Ticket is for service '{ticket_svc}', not '{service}'"), cors)

    # Decrypt with our own encryption key
    key = get_encryption_key()
    try:
        # Read encrypted token from local storage
        stored_doc = kv_store["tokens"].get(service)
        if not stored_doc:
            log.warning("credential_token_not_found rid=%s service=%s", rid, service)
            return _cors_response(error_response(404, "token_not_found", f"No token stored for service '{service}'"), cors)

        # Two storage formats:
        #   Encrypted (via browser-direct /v1/store):
        #     {"v": 1, "alg": "AES-256-GCM", "fields": {...}, "meta": {...}}
        #   Plaintext (via backend /v1/storage set):
        #     {"accessToken": "...", "refreshToken": "...", ...}
        if "fields" in stored_doc:
            # Encrypted format — decrypt all fields
            fields = stored_doc["fields"]
            meta = stored_doc.get("meta", {})
            token = {}
            for field_name, encrypted_value in fields.items():
                if encrypted_value:
                    token[field_name] = decrypt(key, encrypted_value, rid)
            for meta_key, meta_value in meta.items():
                if meta_key not in token:
                    token[meta_key] = meta_value
        else:
            # Plaintext format — return as-is (strip internal fields)
            token = {k: v for k, v in stored_doc.items() if k != "id"}
            log.info("credential_plaintext rid=%s service=%s", rid, service)

        # ── GCP Service Account interception ─────────────────────────
        # If the stored credential is a GCP SA JSON key, mint a
        # short-lived access token instead of returning the raw key.
        raw_access = token.get("accessToken", "")
        if raw_access and is_gcp_service_account(raw_access):
            log.info("credential_gcp_sa_detected rid=%s service=%s", rid, service)
            try:
                # Parse scopes from query param or token metadata
                scopes_param = request.query_params.get("scopes", "")
                scopes = [s.strip() for s in scopes_param.split(",") if s.strip()] or None

                minted = mint_access_token(raw_access, service, scopes=scopes, rid=rid)
                token = {
                    "accessToken": minted["accessToken"],
                    "tokenType": minted["tokenType"],
                    "expiresAt": minted["expiresAt"],
                    "serviceName": service,
                    "serviceAccount": minted["serviceAccount"],
                    "gcpMinted": True,
                }
            except Exception as gcp_err:
                log.exception("credential_gcp_mint_failed rid=%s", rid)
                return _cors_response(
                    error_response(500, "gcp_mint_failed", f"Failed to mint GCP access token: {gcp_err}"),
                    cors,
                )
        # ─────────────────────────────────────────────────────────────

        resp = JSONResponse(
            content={"token": token},
            headers=cors,
        )

    except Exception as e:
        log.exception("credential_failed rid=%s", rid)
        return _cors_response(error_response(500, "internal_error", f"Credential retrieval failed: {e}"), cors)

    log.info(
        "credential_exit rid=%s service=%s purpose=%s sub=%s aid=%s",
        rid, service, payload.get("pur"), payload.get("sub"), payload.get("aid"),
    )
    return resp
