import base64
import hashlib
import hmac as hmac_lib
import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import httpx
import pyshamir
from cachetools import TTLCache
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

LOG_LEVEL = os.environ.get("LOG_LEVEL", "DEBUG").upper()
LOG_FILE = os.environ.get("TOKENVAULT_LOG_FILE", "/data/tokenvault-webhook.log")

log = logging.getLogger("tokenvault-webhook")
log.setLevel(LOG_LEVEL)

_log_fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")

# Console handler
_console_h = logging.StreamHandler()
_console_h.setFormatter(_log_fmt)
log.addHandler(_console_h)

# File handler (with rotation so logs don't fill the Pi's SD card)
try:
    from logging.handlers import RotatingFileHandler
    Path(LOG_FILE).parent.mkdir(parents=True, exist_ok=True)
    _file_h = RotatingFileHandler(LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3)
    _file_h.setFormatter(_log_fmt)
    log.addHandler(_file_h)
    log.info("file_logging_enabled path=%s", LOG_FILE)
except Exception as _log_err:
    log.warning("file_logging_failed path=%s err=%s", LOG_FILE, _log_err)

WEBHOOK_VERSION = "1.0.0"
CAPABILITIES = ["refresh", "decrypt", "storage"]

app = FastAPI(
    title="TokenVault webhook service",
    version=WEBHOOK_VERSION,
)

TIMESTAMP_TOLERANCE = 300  # 5 minutes
OAUTH_TIMEOUT = 10  # seconds
STORE_PATH = Path(os.environ.get("TOKENVAULT_STORE_PATH", "/data/tokenvault_store.json"))

# Track seen request IDs to prevent replay (TTL = 10 min, max 10k entries)
_seen_request_ids: TTLCache = TTLCache(maxsize=10_000, ttl=600)

# Track server start time for uptime reporting
_start_time = time.time()


# ── Helpers ──────────────────────────────────────────────────────────────────

def _summarize_bytes(b: bytes, limit: int = 4096) -> str:
    if not b:
        return ""
    if len(b) <= limit:
        return b.decode("utf-8", errors="replace")
    head = b[:limit].decode("utf-8", errors="replace")
    return f"{head}...(+{len(b) - limit} bytes)"


def _safe_json_loads(b: bytes) -> Tuple[Optional[Any], Optional[str]]:
    try:
        return json.loads(b), None
    except Exception as e:
        return None, str(e)


def _error_response(status_code: int, error_code: str, message: str) -> JSONResponse:
    """Return a spec-compliant error response."""
    return JSONResponse(
        status_code=status_code,
        content={"error": error_code, "message": message},
    )


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Request Logging Middleware ───────────────────────────────────────────────

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        rid = request.headers.get("X-TokenVault-Request-Id") or request.headers.get("X-Request-Id") or str(uuid.uuid4())
        request.state.request_id = rid

        start = time.time()
        client = request.client.host if request.client else "unknown"
        method = request.method
        path = request.url.path
        query = request.url.query
        headers = dict(request.headers)

        body_bytes = await request.body()
        request.state.raw_body = body_bytes

        body_json, body_err = _safe_json_loads(body_bytes)
        body_for_log = body_json if body_json is not None else _summarize_bytes(body_bytes)

        log.info(
            "REQ_ENTER rid=%s method=%s path=%s query=%s client=%s",
            rid, method, path, query, client,
        )
        log.debug("REQ_HEADERS rid=%s headers=%s", rid, headers)
        log.debug("REQ_BODY rid=%s body=%s body_err=%s", rid, body_for_log, body_err)

        try:
            response: Response = await call_next(request)
        except Exception:
            duration_ms = int((time.time() - start) * 1000)
            log.exception("REQ_ERROR rid=%s duration_ms=%s", rid, duration_ms)
            raise

        duration_ms = int((time.time() - start) * 1000)
        log.info(
            "REQ_EXIT rid=%s status=%s duration_ms=%s",
            rid,
            getattr(response, "status_code", "unknown"),
            duration_ms,
        )
        response.headers["X-Request-Id"] = rid
        return response


app.add_middleware(RequestLoggingMiddleware)


# ── Persistent Store ─────────────────────────────────────────────────────────

def _ensure_parent_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def _load_store() -> Dict[str, Any]:
    if not STORE_PATH.exists():
        log.warning("store_missing path=%s", str(STORE_PATH))
        return {
            "share": None,
            "hmac_secret": None,
            "vault_fingerprint": None,
            "is_configured": False,
        }

    raw = STORE_PATH.read_text(encoding="utf-8")
    data = json.loads(raw)
    share = data.get("share")
    hmac_secret = data.get("hmac_secret")

    store = {
        "share": (
            None
            if share is None
            else {
                "index": int(share["index"]),
                "data": base64.b64decode(share["data"]),
                "verifyHash": share.get("verifyHash"),
            }
        ),
        "hmac_secret": None if hmac_secret is None else base64.b64decode(hmac_secret),
        "vault_fingerprint": data.get("vault_fingerprint"),
        "is_configured": data.get("is_configured", share is not None),
    }

    log.info(
        "store_loaded path=%s hasShare=%s hasHmac=%s vaultFingerprint=%s is_configured=%s",
        str(STORE_PATH),
        store["share"] is not None,
        store["hmac_secret"] is not None,
        store["vault_fingerprint"],
        store["is_configured"],
    )
    return store


def _save_store(store: Dict[str, Any]) -> None:
    _ensure_parent_dir(STORE_PATH)

    share = store.get("share")
    hmac_secret = store.get("hmac_secret")

    payload = {
        "share": (
            None
            if share is None
            else {
                "index": int(share["index"]),
                "data": base64.b64encode(share["data"]).decode("ascii"),
                "verifyHash": share.get("verifyHash"),
            }
        ),
        "hmac_secret": None if hmac_secret is None else base64.b64encode(hmac_secret).decode("ascii"),
        "vault_fingerprint": store.get("vault_fingerprint"),
        "is_configured": store.get("is_configured", False),
    }

    tmp = STORE_PATH.with_suffix(STORE_PATH.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
    tmp.replace(STORE_PATH)
    log.info("store_saved path=%s", str(STORE_PATH))


_store: Dict[str, Any] = _load_store()


# ── In-memory KV storage for /v1/storage ─────────────────────────────────────

_kv_store: Dict[str, Dict[str, Any]] = {
    "tokens": {},
    "proxy_configs": {},
    "audit": {},
    "vault_config": {},
}

KV_STORE_PATH = Path(os.environ.get("TOKENVAULT_KV_STORE_PATH", "/data/tokenvault_kv_store.json"))


def _load_kv_store() -> None:
    global _kv_store
    if not KV_STORE_PATH.exists():
        log.info("kv_store_missing path=%s — starting fresh", str(KV_STORE_PATH))
        return
    try:
        raw = KV_STORE_PATH.read_text(encoding="utf-8")
        data = json.loads(raw)
        for col in ("tokens", "proxy_configs", "audit", "vault_config"):
            if col in data and isinstance(data[col], dict):
                _kv_store[col] = data[col]
        log.info(
            "kv_store_loaded path=%s tokens=%d proxy_configs=%d audit=%d",
            str(KV_STORE_PATH),
            len(_kv_store["tokens"]),
            len(_kv_store["proxy_configs"]),
            len(_kv_store["audit"]),
        )
    except Exception as e:
        log.warning("kv_store_load_error path=%s err=%s", str(KV_STORE_PATH), e)


def _save_kv_store() -> None:
    _ensure_parent_dir(KV_STORE_PATH)
    tmp = KV_STORE_PATH.with_suffix(KV_STORE_PATH.suffix + ".tmp")
    tmp.write_text(json.dumps(_kv_store, separators=(",", ":")), encoding="utf-8")
    tmp.replace(KV_STORE_PATH)


_load_kv_store()


def _kv_execute(operation: str, collection: str, key: Optional[str], data: Optional[Any], rid: str) -> dict:
    """Execute a KV storage operation. Returns the response dict (without requestId — caller adds it)."""
    if collection not in _kv_store:
        raise ValueError(f"Unknown collection: {collection}")

    if operation == "get":
        if not key:
            raise ValueError("'key' required for get")
        result = _kv_store[collection].get(key)
        log.info("kv_get rid=%s col=%s key=%s found=%s", rid, collection, key, result is not None)
        return {"data": result}

    elif operation == "list":
        items = []
        for k, v in _kv_store[collection].items():
            meta = {}
            if isinstance(v, dict):
                # Extract meta from the stored document's "meta" field if present
                stored_meta = v.get("meta", {})
                if isinstance(stored_meta, dict):
                    meta = dict(stored_meta)
                # Ensure serviceName is present
                if "serviceName" not in meta:
                    meta["serviceName"] = k
                # Also check top-level fields as fallback
                for mkey in ("serviceName", "tokenType", "createdAt", "expiresAt", "tokenId"):
                    if mkey in v and mkey not in meta:
                        meta[mkey] = v[mkey]
            else:
                meta["serviceName"] = k
            item = {"key": k, "meta": meta}
            # For audit collection, include full event data
            if collection == "audit":
                item["data"] = v
            items.append(item)

        # Sort audit items newest-first by timestamp
        if collection == "audit":
            items.sort(
                key=lambda x: (
                    x.get("data", {}).get("timestamp", "")
                    if isinstance(x.get("data"), dict) else ""
                ),
                reverse=True,
            )

        log.info("kv_list rid=%s col=%s count=%d", rid, collection, len(items))
        return {"items": items}

    elif operation == "set":
        if not key:
            raise ValueError("'key' required for set")
        _kv_store[collection][key] = data
        _save_kv_store()
        log.info("kv_set rid=%s col=%s key=%s", rid, collection, key)
        return {"status": "ok"}

    elif operation == "delete":
        if not key:
            raise ValueError("'key' required for delete")
        _kv_store[collection].pop(key, None)
        _save_kv_store()
        log.info("kv_delete rid=%s col=%s key=%s", rid, collection, key)
        return {"status": "ok"}

    else:
        raise ValueError(f"Unknown operation: {operation}")


# ── Authentication ───────────────────────────────────────────────────────────

def _verify_hmac(
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
    if not _store.get("is_configured") or _store["hmac_secret"] is None:
        return _error_response(403, "setup_required", "Webhook not configured. Run /v1/setup first.")

    sig_header = signature_header or ""
    timestamp = timestamp_header or ""

    if not sig_header.startswith("sha256=") or not timestamp:
        log.warning("hmac_headers_invalid rid=%s sig=%s ts=%s", rid, sig_header, timestamp)
        return _error_response(401, "auth_failed", "Missing or invalid authentication headers")

    # Timestamp validation
    try:
        ts = int(timestamp)
        skew = abs(time.time() - ts)
        if skew > TIMESTAMP_TOLERANCE:
            log.warning("hmac_replay_window rid=%s ts=%s skew=%s", rid, ts, int(skew))
            return _error_response(401, "auth_failed", "Request timestamp outside acceptable window")
    except ValueError:
        log.warning("hmac_timestamp_invalid rid=%s timestamp=%s", rid, timestamp)
        return _error_response(401, "auth_failed", "Invalid timestamp format")

    # Duplicate request ID check
    if request_id:
        if request_id in _seen_request_ids:
            log.warning("hmac_duplicate_request_id rid=%s request_id=%s", rid, request_id)
            return _error_response(401, "auth_failed", "Duplicate request ID")
        _seen_request_ids[request_id] = True

    # HMAC verification
    signing_payload = f"{timestamp}.{body_bytes.decode('utf-8', errors='strict')}"
    expected = hmac_lib.new(
        _store["hmac_secret"],
        signing_payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    ok = hmac_lib.compare_digest(expected, sig_header[7:])
    if not ok:
        log.warning("hmac_mismatch rid=%s", rid)
        return _error_response(401, "auth_failed", "Invalid HMAC signature")

    log.info("hmac_check rid=%s ok=True", rid)
    return None


def _extract_auth_headers(request: Request):
    """Extract standard auth headers and body bytes from request."""
    rid = getattr(request.state, "request_id", "unknown")
    body_bytes = getattr(request.state, "raw_body", None)
    sig = request.headers.get("X-TokenVault-Signature")
    ts = request.headers.get("X-TokenVault-Timestamp")
    req_id = request.headers.get("X-TokenVault-Request-Id")
    return rid, body_bytes, sig, ts, req_id


# ── Crypto helpers ───────────────────────────────────────────────────────────

def _reconstruct_key(tv_share_data: dict, rid: str) -> bytes:
    """Reconstruct the vault key from TV's share and our stored share.

    Per the TokenVault spec, share `data` already includes the pyshamir
    x-coordinate as the first byte. Pass decoded bytes directly to
    pyshamir.combine — do NOT prepend the JSON `index` field.
    """
    if _store["share"] is None:
        raise ValueError("No share stored — run /v1/setup first")

    # Share data already contains pyshamir x-coordinate as first byte
    our_share = _store["share"]["data"]

    try:
        their_share = base64.b64decode(tv_share_data["data"])
    except Exception as e:
        log.error("key_reconstruct_b64_decode_failed rid=%s err=%s", rid, e)
        raise ValueError(f"Invalid base64 in tokenvaultShare.data: {e}")

    log.info(
        "key_reconstruct rid=%s our_share_len=%s tv_share_len=%s",
        rid, len(our_share), len(their_share),
    )

    key = pyshamir.combine([our_share, their_share])
    log.info("key_reconstruct_done rid=%s key_len=%s", rid, len(key))

    if len(key) not in (16, 24, 32):
        log.error(
            "key_reconstruct_bad_length rid=%s key_len=%s (expected 16, 24, or 32)",
            rid, len(key),
        )
        raise ValueError(
            f"Reconstructed key is {len(key)} bytes — AES-256-GCM requires 16, 24, or 32 bytes. "
            "Shares may be mismatched or corrupted."
        )
    return key


def _verify_vault_fingerprint(key: bytes, rid: str) -> Optional[JSONResponse]:
    """Verify reconstructed key matches stored vault fingerprint. Returns error response or None."""
    expected_fp = _store.get("vault_fingerprint")
    if not expected_fp:
        log.warning("vault_fingerprint_missing rid=%s — skipping verification", rid)
        return None

    # Strip "sha256:" prefix
    expected_hex = expected_fp.replace("sha256:", "")
    actual_hex = hashlib.sha256(key).hexdigest()

    if not hmac_lib.compare_digest(actual_hex, expected_hex):
        log.warning("vault_fingerprint_mismatch rid=%s expected=%s actual=%s", rid, expected_hex, actual_hex)
        return _error_response(422, "reconstruction_failed", "Shamir shares produced wrong key (fingerprint mismatch)")

    log.info("vault_fingerprint_verified rid=%s", rid)
    return None


def _verify_share_hash(index: int, data_b64: str, verify_hash: str, rid: str) -> Optional[JSONResponse]:
    """Verify a share's hash. Returns error response or None."""
    share_data = base64.b64decode(data_b64)
    computed = hashlib.sha256(bytes([index]) + share_data).hexdigest()
    # Strip "sha256:" prefix if present
    expected = verify_hash.replace("sha256:", "")

    if not hmac_lib.compare_digest(computed, expected):
        log.warning("share_hash_mismatch rid=%s computed=%s expected=%s", rid, computed, expected)
        return _error_response(400, "invalid_share", "Share verification hash mismatch")

    log.info("share_hash_verified rid=%s index=%s", rid, index)
    return None


def _decrypt(key: bytes, ciphertext_b64: str, rid: str) -> str:
    # --- validate base64 input ---
    if not ciphertext_b64:
        log.error("decrypt_empty_ciphertext rid=%s", rid)
        raise ValueError("Ciphertext is empty")

    try:
        raw = base64.b64decode(ciphertext_b64)
    except Exception as e:
        log.error("decrypt_b64_decode_failed rid=%s input_len=%s err=%s", rid, len(ciphertext_b64), e)
        raise ValueError(f"Invalid base64 ciphertext: {e}")

    # AES-GCM: 12-byte IV + at least 16-byte auth tag
    if len(raw) < 28:
        log.error("decrypt_raw_too_short rid=%s raw_len=%s (need >= 28)", rid, len(raw))
        raise ValueError(f"Ciphertext too short ({len(raw)} bytes, need at least 28)")

    iv = raw[:12]
    ct_with_tag = raw[12:]
    log.info("decrypt rid=%s raw_len=%s iv_len=%s ct_len=%s", rid, len(raw), len(iv), len(ct_with_tag))

    try:
        pt_bytes = AESGCM(key).decrypt(iv, ct_with_tag, None)
    except Exception as e:
        log.error("decrypt_aesgcm_failed rid=%s err=%s", rid, e)
        raise ValueError(f"AES-GCM decryption failed (wrong key or corrupted ciphertext): {e}")

    try:
        pt = pt_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        log.error("decrypt_utf8_failed rid=%s pt_len=%s err=%s", rid, len(pt_bytes), e)
        raise ValueError(f"Decrypted bytes are not valid UTF-8: {e}")

    log.info("decrypt_done rid=%s plaintext_len=%s", rid, len(pt))
    return pt


def _encrypt(key: bytes, plaintext: str, rid: str) -> str:
    iv = os.urandom(12)
    ct_with_tag = AESGCM(key).encrypt(iv, plaintext.encode("utf-8"), None)
    out = base64.b64encode(iv + ct_with_tag).decode("ascii")
    log.info("encrypt rid=%s plaintext_len=%s out_len=%s", rid, len(plaintext), len(out))
    return out


def _decrypt_token_field(key: bytes, encrypted_doc: dict, field: str, rid: str) -> Optional[str]:
    """Decrypt a field from an encrypted token document's 'fields' dict."""
    fields = encrypted_doc.get("fields", {})
    encrypted_value = fields.get(field)
    if not encrypted_value:
        return None
    return _decrypt(key, encrypted_value, rid)


def _build_encrypted_token_document(
    key: bytes,
    access_token: Optional[str],
    refresh_token: Optional[str],
    meta: dict,
    rid: str,
) -> dict:
    """Build a spec-compliant encrypted token document."""
    fields = {}
    if access_token is not None:
        fields["accessToken"] = _encrypt(key, access_token, rid)
    if refresh_token is not None:
        fields["refreshToken"] = _encrypt(key, refresh_token, rid)

    return {
        "v": 1,
        "alg": "AES-256-GCM",
        "fields": fields,
        "meta": meta,
    }


# ── Endpoints ────────────────────────────────────────────────────────────────

@app.post("/v1/setup")
async def setup(request: Request):
    rid = getattr(request.state, "request_id", "unknown")
    log.info("setup_enter rid=%s", rid)

    # Reject if already configured
    if _store.get("is_configured"):
        log.warning("setup_already_configured rid=%s", rid)
        return _error_response(409, "already_configured", "Already configured. Reset the webhook to reconfigure.")

    body_bytes = getattr(request.state, "raw_body", None)
    if body_bytes is None:
        body_bytes = await request.body()

    data, err = _safe_json_loads(body_bytes)
    if data is None:
        return _error_response(400, "invalid_request", f"Invalid JSON: {err}")

    share = data.get("share")
    hmac_secret_b64 = data.get("hmacSecret")

    if not share or not hmac_secret_b64:
        log.warning("setup_missing_fields rid=%s", rid)
        return _error_response(400, "invalid_request", "Missing share or hmacSecret")

    # Verify share hash
    verify_hash = share.get("verifyHash", "")
    if verify_hash:
        hash_err = _verify_share_hash(int(share["index"]), share["data"], verify_hash, rid)
        if hash_err is not None:
            return hash_err

    # Store everything
    _store["share"] = {
        "index": int(share["index"]),
        "data": base64.b64decode(share["data"]),
        "verifyHash": share.get("verifyHash"),
    }
    _store["hmac_secret"] = base64.b64decode(hmac_secret_b64)
    _store["vault_fingerprint"] = data.get("vaultFingerprint")
    _store["is_configured"] = True

    log.info(
        "setup_store rid=%s share_index=%s vault_fingerprint=%s",
        rid, _store["share"]["index"], _store["vault_fingerprint"],
    )

    _save_store(_store)

    resp = {
        "status": "configured",
        "webhookVersion": WEBHOOK_VERSION,
        "capabilities": CAPABILITIES,
    }
    log.info("setup_exit rid=%s response=%s", rid, resp)
    return resp


@app.get("/v1/health")
@app.post("/v1/health")
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

        auth_err = _verify_hmac(body_bytes, sig, ts, req_id, rid)
        if auth_err is not None:
            return auth_err

    uptime = int(time.time() - _start_time)

    resp = {
        "status": "healthy",
        "version": WEBHOOK_VERSION,
        "shareConfigured": _store.get("is_configured", False),
        "capabilities": CAPABILITIES,
        "uptime": uptime,
    }
    log.info("health rid=%s response=%s", rid, resp)
    return resp


@app.post("/v1/decrypt")
async def decrypt(request: Request):
    rid, body_bytes, sig, ts, req_id = _extract_auth_headers(request)
    log.info("decrypt_enter rid=%s", rid)

    if body_bytes is None:
        body_bytes = await request.body()

    auth_err = _verify_hmac(body_bytes, sig, ts, req_id, rid)
    if auth_err is not None:
        return auth_err

    data, err = _safe_json_loads(body_bytes)
    if data is None:
        return _error_response(400, "invalid_request", f"Invalid JSON: {err}")

    request_id = data.get("requestId", req_id or rid)
    tv_share = data.get("tokenvaultShare")
    encrypted_doc = data.get("encryptedDocument")
    purpose = data.get("purpose", "user_request")
    service_name = data.get("serviceName", "unknown")

    if not tv_share:
        return _error_response(400, "invalid_request", "Missing tokenvaultShare")
    if not encrypted_doc:
        return _error_response(400, "invalid_request", "Missing encryptedDocument")

    # Optionally verify TV's share hash
    tv_verify_hash = tv_share.get("verifyHash")
    if tv_verify_hash:
        hash_err = _verify_share_hash(int(tv_share["index"]), tv_share["data"], tv_verify_hash, rid)
        if hash_err is not None:
            return hash_err

    key = None
    try:
        key = _reconstruct_key(tv_share, rid)

        # Verify vault fingerprint
        fp_err = _verify_vault_fingerprint(key, rid)
        if fp_err is not None:
            return fp_err

        # Decrypt ALL encrypted fields in the document
        fields = encrypted_doc.get("fields", {})
        meta = encrypted_doc.get("meta", {})
        token = {}

        for field_name, encrypted_value in fields.items():
            if encrypted_value:
                token[field_name] = _decrypt(key, encrypted_value, rid)

        # Merge metadata into token response
        for meta_key, meta_value in meta.items():
            if meta_key not in token:
                token[meta_key] = meta_value

        resp = {
            "requestId": request_id,
            "token": token,
        }

    except Exception as e:
        log.exception("decrypt_failed rid=%s", rid)
        return _error_response(500, "internal_error", f"Decryption failed: {e}")
    finally:
        # Zero out key
        if key is not None:
            key = b'\x00' * len(key)

    log.info("decrypt_exit rid=%s purpose=%s service=%s", rid, purpose, service_name)
    return resp


@app.post("/v1/refresh")
async def refresh(request: Request):
    rid, body_bytes, sig, ts, req_id = _extract_auth_headers(request)
    log.info("refresh_enter rid=%s", rid)

    if body_bytes is None:
        body_bytes = await request.body()

    auth_err = _verify_hmac(body_bytes, sig, ts, req_id, rid)
    if auth_err is not None:
        return auth_err

    data, err = _safe_json_loads(body_bytes)
    if data is None:
        return _error_response(400, "invalid_request", f"Invalid JSON: {err}")

    request_id = data.get("requestId", req_id or rid)
    tv_share = data.get("tokenvaultShare")
    encrypted_refresh = data.get("encryptedRefreshToken", "")
    provider = data.get("provider", {})
    repo_info = data.get("repoInfo", {})

    if not tv_share:
        return _error_response(400, "invalid_request", "Missing tokenvaultShare")

    # Optionally verify TV's share hash
    tv_verify_hash = tv_share.get("verifyHash")
    if tv_verify_hash:
        hash_err = _verify_share_hash(int(tv_share["index"]), tv_share["data"], tv_verify_hash, rid)
        if hash_err is not None:
            return hash_err

    # Determine refresh mode
    # Mode A (server): encryptedRefreshToken is non-empty — TV provides the token
    # Mode B (webhook): encryptedRefreshToken is empty — read from local storage
    is_webhook_mode = not encrypted_refresh
    service_name = repo_info.get("serviceName", "unknown")

    key = None
    try:
        key = _reconstruct_key(tv_share, rid)

        # Verify vault fingerprint
        fp_err = _verify_vault_fingerprint(key, rid)
        if fp_err is not None:
            return fp_err

        if is_webhook_mode:
            # Mode B: Read encrypted token from local storage
            stored_doc = _kv_store["tokens"].get(service_name)
            if not stored_doc:
                return _error_response(400, "invalid_request", f"No stored token for service '{service_name}'")

            refresh_token_plaintext = _decrypt_token_field(key, stored_doc, "refreshToken", rid)
            if not refresh_token_plaintext:
                return _error_response(400, "invalid_request", f"No refreshToken found in stored document for '{service_name}'")

            existing_meta = stored_doc.get("meta", {})
        else:
            # Mode A: Decrypt the provided encrypted refresh token
            # The encryptedRefreshToken could be a full document or just the encrypted field
            # Try to parse as a document first
            try:
                doc = json.loads(base64.b64decode(encrypted_refresh)) if encrypted_refresh.startswith("ey") else None
            except Exception:
                doc = None

            if doc and "fields" in doc:
                refresh_token_plaintext = _decrypt_token_field(key, doc, "refreshToken", rid)
                existing_meta = doc.get("meta", {})
            else:
                # It's a raw encrypted field value
                refresh_token_plaintext = _decrypt(key, encrypted_refresh, rid)
                existing_meta = {}

            if not refresh_token_plaintext:
                return _error_response(400, "invalid_request", "Could not decrypt refresh token")

        # Call OAuth provider's token endpoint
        token_url = provider.get("tokenUrl")
        client_id = provider.get("clientId")
        client_secret = provider.get("clientSecret")

        if token_url and client_id and client_secret:
            # Real OAuth refresh
            form_data = {
                "grant_type": "refresh_token",
                "client_id": client_id,
                "client_secret": client_secret,
                "refresh_token": refresh_token_plaintext,
            }
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            # GitHub needs Accept: application/json
            provider_name = provider.get("provider", "").lower()
            if provider_name == "github":
                headers["Accept"] = "application/json"

            log.info("refresh_oauth_call rid=%s token_url=%s provider=%s", rid, token_url, provider_name)

            try:
                async with httpx.AsyncClient(timeout=OAUTH_TIMEOUT) as client:
                    oauth_resp = await client.post(token_url, data=form_data, headers=headers)

                if oauth_resp.status_code >= 400:
                    log.warning("refresh_oauth_error rid=%s status=%s body=%s", rid, oauth_resp.status_code, oauth_resp.text)
                    return _error_response(502, "provider_error", f"OAuth provider returned {oauth_resp.status_code}: {oauth_resp.text}")

                oauth_data = oauth_resp.json()
                new_access_token = oauth_data.get("access_token", "")
                new_refresh_token = oauth_data.get("refresh_token", refresh_token_plaintext)
                expires_in = oauth_data.get("expires_in", 3600)

            except httpx.TimeoutException:
                return _error_response(504, "provider_timeout", "OAuth provider did not respond within timeout")
            except Exception as e:
                log.exception("refresh_oauth_failed rid=%s", rid)
                return _error_response(502, "provider_error", f"OAuth provider request failed: {e}")
        else:
            # No provider info — generate synthetic tokens (test/fallback mode)
            log.warning("refresh_no_provider rid=%s — generating synthetic tokens", rid)
            new_access_token = f"refreshed-access-token-{int(time.time())}"
            new_refresh_token = refresh_token_plaintext  # Keep same refresh token
            expires_in = 3600

        # Build updated meta
        expiry_ms = int((time.time() + expires_in) * 1000)
        updated_meta = {
            "serviceName": service_name,
            "tokenType": existing_meta.get("tokenType", provider.get("provider", "oauth")),
            "expiryTime": expiry_ms,
            "updatedAt": _now_iso(),
        }
        # Preserve createdAt from original
        if "createdAt" in existing_meta:
            updated_meta["createdAt"] = existing_meta["createdAt"]

        # Build encrypted token document
        encrypted_doc = _build_encrypted_token_document(
            key, new_access_token, new_refresh_token, updated_meta, rid,
        )

        # Mode B: store updated document locally
        if is_webhook_mode:
            _kv_store["tokens"][service_name] = encrypted_doc
            _save_kv_store()
            log.info("refresh_stored_locally rid=%s service=%s", rid, service_name)

        resp = {
            "requestId": request_id,
            "status": "refreshed",
            "encryptedTokenDocument": encrypted_doc,
        }

    except Exception as e:
        log.exception("refresh_failed rid=%s", rid)
        return _error_response(500, "internal_error", f"Refresh failed: {e}")
    finally:
        if key is not None:
            key = b'\x00' * len(key)

    log.info("refresh_exit rid=%s status=refreshed", rid)
    return resp


@app.post("/v1/get_share")
async def get_share(request: Request):
    rid, body_bytes, sig, ts, req_id = _extract_auth_headers(request)
    log.info("get_share_enter rid=%s", rid)

    if body_bytes is None:
        body_bytes = await request.body()

    auth_err = _verify_hmac(body_bytes, sig, ts, req_id, rid)
    if auth_err is not None:
        return auth_err

    data, err = _safe_json_loads(body_bytes)
    if data is None:
        return _error_response(400, "invalid_request", f"Invalid JSON: {err}")

    request_id = data.get("requestId", req_id or rid)

    if _store["share"] is None:
        return _error_response(403, "setup_required", "No share configured on webhook")

    # Optionally verify TV's share hash (defense in depth)
    tv_share = data.get("tokenvaultShare")
    if tv_share and tv_share.get("verifyHash"):
        hash_err = _verify_share_hash(int(tv_share["index"]), tv_share["data"], tv_share["verifyHash"], rid)
        if hash_err is not None:
            return hash_err

    resp = {
        "requestId": request_id,
        "share": {
            "index": _store["share"]["index"],
            "data": base64.b64encode(_store["share"]["data"]).decode("ascii"),
            "verifyHash": _store["share"].get("verifyHash"),
        },
    }
    log.info("get_share_exit rid=%s", rid)
    return resp


@app.post("/v1/notify_expiry")
async def notify_expiry(request: Request):
    rid, body_bytes, sig, ts, req_id = _extract_auth_headers(request)
    log.info("notify_expiry_enter rid=%s", rid)

    if body_bytes is None:
        body_bytes = await request.body()

    auth_err = _verify_hmac(body_bytes, sig, ts, req_id, rid)
    if auth_err is not None:
        return auth_err

    data, err = _safe_json_loads(body_bytes)
    if data is None:
        return _error_response(400, "invalid_request", f"Invalid JSON: {err}")

    request_id = data.get("requestId", req_id or rid)
    service_name = data.get("serviceName", "unknown")
    expires_at = data.get("expiresAt")
    token_type = data.get("tokenType")

    log.info(
        "notify_expiry rid=%s service=%s expires_at=%s token_type=%s",
        rid, service_name, expires_at, token_type,
    )

    return {
        "requestId": request_id,
        "status": "acknowledged",
    }


@app.post("/v1/storage")
async def storage_http(request: Request):
    rid, body_bytes, sig, ts, req_id = _extract_auth_headers(request)

    if body_bytes is None:
        body_bytes = await request.body()

    auth_err = _verify_hmac(body_bytes, sig, ts, req_id, rid)
    if auth_err is not None:
        return auth_err

    data, err = _safe_json_loads(body_bytes)
    if data is None:
        return _error_response(400, "invalid_request", f"Invalid JSON: {err}")

    request_id = data.get("requestId", req_id or rid)
    operation = data.get("operation")
    collection = data.get("collection")
    key = data.get("key")
    payload = data.get("data")

    if not operation or not collection:
        return _error_response(400, "invalid_request", "Missing 'operation' or 'collection'")

    try:
        result = _kv_execute(operation, collection, key, payload, rid)
    except ValueError as e:
        return _error_response(400, "invalid_request", str(e))

    # Add requestId to every response
    result["requestId"] = request_id
    return result


# ── Entrypoint ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
