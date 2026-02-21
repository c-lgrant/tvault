import time

from fastapi import APIRouter, Request

from auth import extract_auth_headers, verify_hmac
from config import CAPABILITIES, WEBHOOK_VERSION, error_response, log, start_time
from middleware import safe_json_loads
from store import kv_store, kv_execute, store

router = APIRouter()


@router.get("/v1/health")
@router.post("/v1/health")
async def health(request: Request):
    rid = getattr(request.state, "request_id", "unknown")

    # POST requests require HMAC authentication; GET does not
    if request.method == "POST":
        body_bytes = getattr(request.state, "raw_body", None)
        if body_bytes is None:
            body_bytes = await request.body()

        sig = request.headers.get("X-TokenVault-Signature")
        ts = request.headers.get("X-TokenVault-Timestamp")
        req_id = request.headers.get("X-TokenVault-Request-Id")

        auth_err = verify_hmac(body_bytes, sig, ts, req_id, rid)
        if auth_err is not None:
            return auth_err

    uptime = int(time.time() - start_time)

    resp = {
        "status": "healthy",
        "version": WEBHOOK_VERSION,
        "keyConfigured": store.get("encryption_key") is not None,
        "capabilities": CAPABILITIES,
        "uptime": uptime,
        "tokenCount": len(kv_store["tokens"]),
    }
    log.info("health rid=%s response=%s", rid, resp)
    return resp


# ── KV Storage (for TV backend metadata operations) ──────────────────────────

@router.post("/v1/storage")
async def storage_http(request: Request):
    rid, body_bytes, sig, ts, req_id = extract_auth_headers(request)

    if body_bytes is None:
        body_bytes = await request.body()

    auth_err = verify_hmac(body_bytes, sig, ts, req_id, rid)
    if auth_err is not None:
        return auth_err

    data, err = safe_json_loads(body_bytes)
    if data is None:
        return error_response(400, "invalid_request", f"Invalid JSON: {err}")

    request_id = data.get("requestId", req_id or rid)
    operation = data.get("operation")
    collection = data.get("collection")
    key = data.get("key")
    payload = data.get("data")

    if not operation or not collection:
        return error_response(400, "invalid_request", "Missing 'operation' or 'collection'")

    try:
        result = kv_execute(operation, collection, key, payload, rid)
    except ValueError as e:
        return error_response(400, "invalid_request", str(e))

    # Add requestId to every response
    result["requestId"] = request_id
    return result
