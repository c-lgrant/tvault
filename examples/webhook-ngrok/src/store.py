import atexit
import base64
import hashlib
import json
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

from config import KV_STORE_PATH, SENSITIVE_FIELDS, STORE_PATH, log


def ensure_parent_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def generate_keys() -> Dict[str, Any]:
    """Generate a fresh set of encryption key and HMAC secret."""
    encryption_key = os.urandom(32)  # AES-256
    hmac_secret = os.urandom(32)
    webhook_id = str(uuid.uuid4())
    hmac_secret_hash = hashlib.sha256(hmac_secret).hexdigest()

    log.info(
        "keys_generated webhook_id=%s hmac_hash=%s",
        webhook_id, hmac_secret_hash,
    )

    return {
        "webhook_id": webhook_id,
        "encryption_key": encryption_key,
        "hmac_secret": hmac_secret,
        "hmac_secret_hash": hmac_secret_hash,
        "tokenvault_origin": "",
        "is_configured": True,
    }


def save_store(store_data: Dict[str, Any]) -> None:
    ensure_parent_dir(STORE_PATH)

    payload = {
        "webhook_id": store_data.get("webhook_id", ""),
        "encryption_key": base64.b64encode(store_data["encryption_key"]).decode("ascii"),
        "hmac_secret": base64.b64encode(store_data["hmac_secret"]).decode("ascii"),
        "hmac_secret_hash": store_data.get("hmac_secret_hash", ""),
        "tokenvault_origin": store_data.get("tokenvault_origin", ""),
        "is_configured": store_data.get("is_configured", False),
    }

    tmp = STORE_PATH.with_suffix(STORE_PATH.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
    tmp.replace(STORE_PATH)
    log.info("store_saved path=%s", str(STORE_PATH))


def load_store() -> Dict[str, Any]:
    if not STORE_PATH.exists():
        log.warning("store_missing path=%s — generating fresh keys", str(STORE_PATH))
        s = generate_keys()
        save_store(s)
        return s

    raw = STORE_PATH.read_text(encoding="utf-8")
    data = json.loads(raw)

    # Load v2 fields (webhook-sovereign)
    encryption_key_b64 = data.get("encryption_key")
    hmac_secret_b64 = data.get("hmac_secret")

    if encryption_key_b64 and hmac_secret_b64:
        # v2 store format
        s = {
            "webhook_id": data.get("webhook_id", str(uuid.uuid4())),
            "encryption_key": base64.b64decode(encryption_key_b64),
            "hmac_secret": base64.b64decode(hmac_secret_b64),
            "hmac_secret_hash": data.get("hmac_secret_hash", ""),
            "tokenvault_origin": data.get("tokenvault_origin", ""),
            "is_configured": data.get("is_configured", True),
        }
        # Recompute hash if missing
        if not s["hmac_secret_hash"]:
            s["hmac_secret_hash"] = hashlib.sha256(s["hmac_secret"]).hexdigest()

        log.info(
            "store_loaded_v2 path=%s webhook_id=%s hasKey=%s hasHmac=%s origin=%s",
            str(STORE_PATH),
            s["webhook_id"],
            s["encryption_key"] is not None,
            s["hmac_secret"] is not None,
            s["tokenvault_origin"],
        )
        return s

    # Unrecognised store format — generate fresh keys
    log.warning("store_unrecognised path=%s — generating fresh keys", str(STORE_PATH))
    s = generate_keys()
    save_store(s)
    return s


# Module-level store (loaded on import)
store: Dict[str, Any] = load_store()


# ── In-memory KV storage ─────────────────────────────────────────────────────

kv_store: Dict[str, Dict[str, Any]] = {
    "tokens": {},
    "proxy_configs": {},
    "audit": {},
    "vault_config": {},
}


def load_kv_store() -> None:
    global kv_store
    if not KV_STORE_PATH.exists():
        log.info("kv_store_missing path=%s — starting fresh", str(KV_STORE_PATH))
        return
    try:
        raw = KV_STORE_PATH.read_text(encoding="utf-8")
        data = json.loads(raw)
        for col in ("tokens", "proxy_configs", "audit", "vault_config"):
            if col in data and isinstance(data[col], dict):
                kv_store[col] = data[col]
        log.info(
            "kv_store_loaded path=%s tokens=%d proxy_configs=%d audit=%d",
            str(KV_STORE_PATH),
            len(kv_store["tokens"]),
            len(kv_store["proxy_configs"]),
            len(kv_store["audit"]),
        )
    except Exception as e:
        log.warning("kv_store_load_error path=%s err=%s", str(KV_STORE_PATH), e)


_kv_dirty = False
_kv_save_lock = threading.Lock()


def _flush_kv_store() -> None:
    """Write kv_store to disk (must hold _kv_save_lock)."""
    ensure_parent_dir(KV_STORE_PATH)
    tmp = KV_STORE_PATH.with_suffix(KV_STORE_PATH.suffix + ".tmp")
    tmp.write_text(json.dumps(kv_store, separators=(",", ":")), encoding="utf-8")
    tmp.replace(KV_STORE_PATH)


def save_kv_store() -> None:
    with _kv_save_lock:
        _flush_kv_store()


def _mark_kv_dirty() -> None:
    global _kv_dirty
    _kv_dirty = True


def _background_kv_saver() -> None:
    """Flush kv_store to disk every 1s if dirty."""
    global _kv_dirty
    while True:
        time.sleep(1)
        if _kv_dirty:
            with _kv_save_lock:
                if _kv_dirty:
                    _flush_kv_store()
                    _kv_dirty = False


_saver_thread = threading.Thread(target=_background_kv_saver, daemon=True)
_saver_thread.start()


def _flush_on_exit() -> None:
    global _kv_dirty
    with _kv_save_lock:
        if _kv_dirty:
            _flush_kv_store()
            _kv_dirty = False


atexit.register(_flush_on_exit)


load_kv_store()


def kv_execute(operation: str, collection: str, key: Optional[str], data: Optional[Any], rid: str,
               collections: Optional[list] = None, options: Optional[dict] = None) -> dict:
    """Execute a KV storage operation. Returns the response dict (without requestId — caller adds it).

    Args:
        options: Optional dict with pagination/filter options for list operations.
            Keys: limit (int), after (str cursor), filters (dict of field=value).
    """
    if operation == "list_batch":
        if not collections:
            raise ValueError("'collections' required for list_batch")
        results = {}
        for col in collections:
            if col not in kv_store:
                continue
            # Re-use the existing list logic by recursing with operation="list"
            results[col] = kv_execute("list", col, None, None, rid, options=options)
        log.info("kv_list_batch rid=%s collections=%s", rid, list(results.keys()))
        return {"results": results}

    if collection not in kv_store:
        raise ValueError(f"Unknown collection: {collection}")

    if operation == "get":
        if not key:
            raise ValueError("'key' required for get")
        result = kv_store[collection].get(key)
        log.info("kv_get rid=%s col=%s key=%s found=%s", rid, collection, key, result is not None)
        return {"data": result}

    elif operation == "list":
        items = []
        for k, v in kv_store[collection].items():
            meta = {}
            if isinstance(v, dict):
                # Extract meta from the stored document's "meta" field if present
                # (encrypted documents have {"v": 1, "fields": {...}, "meta": {...}})
                stored_meta = v.get("meta", {})
                if isinstance(stored_meta, dict):
                    meta = dict(stored_meta)
                # Ensure serviceName is present
                if "serviceName" not in meta:
                    meta["serviceName"] = k
                # For plaintext tokens (stored via /v1/storage set from backend),
                # all metadata lives at the top level. Extract everything except
                # sensitive credential fields and internal encryption fields.
                for mkey, mval in v.items():
                    if mkey not in meta and mkey not in SENSITIVE_FIELDS and mkey not in ("v", "alg", "fields", "meta"):
                        meta[mkey] = mval
                # Ensure hasRefreshToken is set for plaintext tokens
                if "hasRefreshToken" not in meta and "refreshToken" in v:
                    meta["hasRefreshToken"] = bool(v["refreshToken"])
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

        # Apply options (pagination + filters) if provided
        pagination = None
        if options and isinstance(options, dict):
            opt_filters = options.get("filters")
            opt_after = options.get("after")
            opt_limit = options.get("limit")

            # Apply filters: match each filter key against item data fields (AND logic)
            if opt_filters and isinstance(opt_filters, dict):
                filtered = []
                for item in items:
                    # Match against data (audit) or meta (other collections)
                    match_src = item.get("data") if isinstance(item.get("data"), dict) else item.get("meta", {})
                    if all(match_src.get(fk) == fv for fk, fv in opt_filters.items()):
                        filtered.append(item)
                items = filtered

            total_count = len(items)

            # Apply cursor: for audit, skip items with timestamp >= after;
            # for other collections, skip items with key >= after
            if opt_after:
                if collection == "audit":
                    items = [
                        item for item in items
                        if (item.get("data", {}).get("timestamp", "") if isinstance(item.get("data"), dict) else item.get("key", "")) < opt_after
                    ]
                else:
                    items = [item for item in items if item.get("key", "") > opt_after]

            # Apply limit and compute pagination
            if opt_limit and isinstance(opt_limit, int) and opt_limit > 0:
                has_more = len(items) > opt_limit
                items = items[:opt_limit]
                if collection == "audit" and items:
                    last_ts = items[-1].get("data", {}).get("timestamp", "") if isinstance(items[-1].get("data"), dict) else items[-1].get("key", "")
                    next_cursor = last_ts if has_more else None
                else:
                    next_cursor = items[-1].get("key", "") if has_more and items else None
                pagination = {
                    "hasMore": has_more,
                    "nextCursor": next_cursor,
                    "totalCount": total_count,
                }

        log.info("kv_list rid=%s col=%s count=%d", rid, collection, len(items))
        result = {"items": items}
        if pagination is not None:
            result["pagination"] = pagination
        return result

    elif operation == "set":
        if not key:
            raise ValueError("'key' required for set")
        kv_store[collection][key] = data
        _mark_kv_dirty()
        log.info("kv_set rid=%s col=%s key=%s", rid, collection, key)
        return {"status": "ok"}

    elif operation == "delete":
        if not key:
            raise ValueError("'key' required for delete")
        kv_store[collection].pop(key, None)
        _mark_kv_dirty()
        log.info("kv_delete rid=%s col=%s key=%s", rid, collection, key)
        return {"status": "ok"}

    else:
        raise ValueError(f"Unknown operation: {operation}")
