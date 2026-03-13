"""TOTP code generation endpoint.

Generates the current one-time code from a stored TOTP secret without
Token Vault ever seeing the secret.  Follows the same ticket-based
authentication pattern as ``/v1/credential``.
"""

import time

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from auth import cors_headers, verify_ticket
from config import error_response, log
from crypto import decrypt, decrypt_token_field, get_encryption_key
from store import kv_store

router = APIRouter()


def _cors_response(resp: Response, cors: dict) -> Response:
    for k, v in cors.items():
        resp.headers[k] = v
    return resp


def _generate_totp_code(secret: str, stored_doc: dict) -> dict:
    """Generate a TOTP code from a decrypted secret and token metadata."""
    import pyotp

    meta = stored_doc.get("meta", {})
    algorithm = meta.get("totpAlgorithm") or stored_doc.get("totpAlgorithm") or "SHA1"
    digits = meta.get("totpDigits") or stored_doc.get("totpDigits") or 6
    period = meta.get("totpPeriod") or stored_doc.get("totpPeriod") or 30

    digest_map = {"SHA1": "sha1", "SHA256": "sha256", "SHA512": "sha512"}
    digest_name = digest_map.get(algorithm.upper(), "sha1")

    totp = pyotp.TOTP(secret, digits=digits, interval=period, digest=digest_name)
    code = totp.now()
    remaining = period - (int(time.time()) % period)

    return {
        "code": code,
        "remainingSeconds": remaining,
        "period": period,
        "digits": digits,
    }


@router.options("/v1/totp-code")
async def totp_preflight(request: Request):
    """CORS preflight for browser-based TOTP code requests."""
    origin = request.headers.get("origin", "")
    return Response(status_code=204, headers=cors_headers(origin))


@router.post("/v1/totp-code")
@router.get("/v1/totp-code")
async def totp_code(request: Request):
    """Zero-knowledge TOTP code generation.

    Decrypts the stored TOTP secret using the webhook's own key and
    generates the current one-time code.  Token Vault never sees the
    secret — it only issues the ticket that authorizes this request.

    Accepts either:
      - POST with JSON body: {"ticket": "...", "service": "..."}
      - GET with query params: ?ticket=...&service=... (from redirect)
    """
    rid = getattr(request.state, "request_id", "unknown")
    log.info("totp_code_enter rid=%s method=%s", rid, request.method)
    request_origin = request.headers.get("origin", "")
    cors = cors_headers(request_origin)

    # Extract ticket and service
    if request.method == "GET":
        ticket = request.query_params.get("ticket", "")
        service = request.query_params.get("service", "")
    else:
        from middleware import safe_json_loads
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

    # Accept same purposes as /v1/credential
    purpose = payload.get("pur")
    if purpose not in ("agent_credential", "user_reveal", "browser_credential", "totp_code"):
        log.warning("totp_code_invalid_purpose rid=%s purpose=%s", rid, purpose)
        return _cors_response(error_response(401, "ticket_invalid", f"Invalid ticket purpose: '{purpose}'"), cors)

    # Verify service matches ticket
    ticket_svc = payload.get("svc", "")
    if ticket_svc != service:
        log.warning("totp_code_service_mismatch rid=%s ticket=%s requested=%s", rid, ticket_svc, service)
        return _cors_response(error_response(401, "ticket_invalid", f"Ticket is for service '{ticket_svc}', not '{service}'"), cors)

    # Decrypt and generate code
    key = get_encryption_key()
    try:
        stored_doc = kv_store["tokens"].get(service)
        if not stored_doc:
            log.warning("totp_code_not_found rid=%s service=%s", rid, service)
            return _cors_response(error_response(404, "token_not_found", f"No token stored for service '{service}'"), cors)

        # Check that this is actually a TOTP token
        meta = stored_doc.get("meta", {})
        token_type = meta.get("tokenType", "") or stored_doc.get("tokenType", "")
        if token_type != "TOTP":
            log.warning("totp_code_wrong_type rid=%s service=%s type=%s", rid, service, token_type)
            return _cors_response(error_response(400, "not_totp", f"Token '{service}' is not a TOTP token (type: {token_type})"), cors)

        # Decrypt the TOTP secret
        if "fields" in stored_doc:
            secret = decrypt_token_field(key, stored_doc, "totpSecret", rid)
        else:
            secret = stored_doc.get("totpSecret")

        if not secret:
            log.warning("totp_code_no_secret rid=%s service=%s", rid, service)
            return _cors_response(error_response(400, "no_totp_secret", "TOTP secret is missing from stored token"), cors)

        result = _generate_totp_code(secret, stored_doc)

        log.info(
            "totp_code_exit rid=%s service=%s sub=%s aid=%s digits=%s",
            rid, service, payload.get("sub"), payload.get("aid"), result["digits"],
        )
        return _cors_response(JSONResponse(content=result), cors)

    except Exception as e:
        log.exception("totp_code_failed rid=%s", rid)
        return _cors_response(error_response(500, "internal_error", f"TOTP code generation failed: {e}"), cors)
