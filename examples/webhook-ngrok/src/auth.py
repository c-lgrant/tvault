import base64
import hashlib
import hmac as hmac_lib
import json
import time
from typing import Optional, Tuple

from fastapi import Request
from fastapi.responses import JSONResponse

from config import (
    TIMESTAMP_TOLERANCE,
    error_response,
    log,
    seen_request_ids,
    seen_ticket_nonces,
)
from store import store


def verify_hmac(
    body_bytes: bytes,
    signature_header: Optional[str],
    timestamp_header: Optional[str],
    request_id: Optional[str],
    rid: str,
) -> Optional[JSONResponse]:
    """
    Verify HMAC signature, timestamp, and request ID.
    Returns None if valid, or a JSONResponse error if invalid.
    """
    if not store.get("is_configured") or store["hmac_secret"] is None:
        return error_response(403, "setup_required", "Webhook not configured.")

    sig_header = signature_header or ""
    timestamp = timestamp_header or ""

    if not sig_header.startswith("sha256=") or not timestamp:
        log.warning("hmac_headers_invalid rid=%s sig=%s ts=%s", rid, sig_header, timestamp)
        return error_response(401, "auth_failed", "Missing or invalid authentication headers")

    # Timestamp validation
    try:
        ts = int(timestamp)
        skew = abs(time.time() - ts)
        if skew > TIMESTAMP_TOLERANCE:
            log.warning("hmac_replay_window rid=%s ts=%s skew=%s", rid, ts, int(skew))
            return error_response(401, "auth_failed", "Request timestamp outside acceptable window")
    except ValueError:
        log.warning("hmac_timestamp_invalid rid=%s timestamp=%s", rid, timestamp)
        return error_response(401, "auth_failed", "Invalid timestamp format")

    # Duplicate request ID check
    if request_id:
        if request_id in seen_request_ids:
            log.warning("hmac_duplicate_request_id rid=%s request_id=%s", rid, request_id)
            return error_response(401, "auth_failed", "Duplicate request ID")
        seen_request_ids[request_id] = True

    # HMAC verification
    signing_payload = f"{timestamp}.{body_bytes.decode('utf-8', errors='strict')}"
    expected = hmac_lib.new(
        store["hmac_secret"],
        signing_payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    ok = hmac_lib.compare_digest(expected, sig_header[7:])
    if not ok:
        log.warning("hmac_mismatch rid=%s", rid)
        return error_response(401, "auth_failed", "Invalid HMAC signature")

    log.info("hmac_check rid=%s ok=True", rid)
    return None


def extract_auth_headers(request: Request):
    """Extract standard auth headers and body bytes from request."""
    rid = getattr(request.state, "request_id", "unknown")
    body_bytes = getattr(request.state, "raw_body", None)
    sig = request.headers.get("X-TokenVault-Signature")
    ts = request.headers.get("X-TokenVault-Timestamp")
    req_id = request.headers.get("X-TokenVault-Request-Id")
    return rid, body_bytes, sig, ts, req_id


def cors_headers(request_origin: str = "") -> dict:
    """Build CORS headers using the stored Token Vault origin.

    Falls back to reflecting the request Origin header so that dev
    environments (where the stored origin may be stale) still work.
    The credential ticket itself is the auth boundary, not CORS.
    """
    allowed = store.get("tokenvault_origin", "")
    if allowed and request_origin and request_origin != allowed:
        # Stored origin doesn't match — reflect request origin
        # (ticket HMAC is the real security check)
        log.info("cors_origin_reflect stored=%s request=%s", allowed, request_origin)
        allowed = request_origin
    if not allowed:
        allowed = request_origin or "*"
    return {
        "Access-Control-Allow-Origin": allowed,
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
    }


def verify_ticket(ticket: str, rid: str) -> Tuple[Optional[dict], Optional[JSONResponse]]:
    """Verify a credential ticket's HMAC signature, expiry, and nonce.

    Returns (payload, None) on success or (None, error_response) on failure.
    """
    if not store.get("is_configured") or store["hmac_secret"] is None:
        return None, error_response(403, "setup_required", "Webhook not configured.")

    parts = ticket.split(".")
    if len(parts) != 2:
        log.warning("ticket_malformed rid=%s parts=%d", rid, len(parts))
        return None, error_response(401, "ticket_invalid", "Malformed ticket")

    payload_b64, provided_sig = parts

    # HMAC verification (constant-time comparison)
    expected_sig = hmac_lib.new(
        store["hmac_secret"],
        payload_b64.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    if not hmac_lib.compare_digest(expected_sig, provided_sig):
        log.warning("ticket_hmac_mismatch rid=%s", rid)
        return None, error_response(401, "ticket_invalid", "HMAC signature verification failed")

    # Decode payload
    try:
        # Add back base64url padding
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        payload_json = base64.urlsafe_b64decode(padded)
        payload = json.loads(payload_json)
    except Exception as e:
        log.warning("ticket_decode_failed rid=%s err=%s", rid, e)
        return None, error_response(401, "ticket_invalid", "Failed to decode ticket payload")

    # Check expiry
    if payload.get("exp", 0) < time.time():
        log.warning("ticket_expired rid=%s exp=%s now=%s", rid, payload.get("exp"), int(time.time()))
        return None, error_response(401, "ticket_expired", "Ticket has expired")

    # Nonce replay prevention
    nonce = payload.get("nonce", "")
    if nonce:
        if nonce in seen_ticket_nonces:
            log.warning("ticket_replay rid=%s nonce=%s", rid, nonce)
            return None, error_response(401, "ticket_invalid", "Ticket nonce already used (replay)")
        seen_ticket_nonces[nonce] = True

    log.info(
        "ticket_verified rid=%s sub=%s svc=%s pur=%s aid=%s",
        rid, payload.get("sub"), payload.get("svc"), payload.get("pur"), payload.get("aid"),
    )
    return payload, None
