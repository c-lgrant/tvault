import json
import time
import uuid
from typing import Any, Optional, Tuple

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from config import log


def summarize_bytes(b: bytes, limit: int = 4096) -> str:
    if not b:
        return ""
    if len(b) <= limit:
        return b.decode("utf-8", errors="replace")
    head = b[:limit].decode("utf-8", errors="replace")
    return f"{head}...(+{len(b) - limit} bytes)"


def safe_json_loads(b: bytes) -> Tuple[Optional[Any], Optional[str]]:
    try:
        return json.loads(b), None
    except Exception as e:
        return None, str(e)


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

        body_json, body_err = safe_json_loads(body_bytes)
        body_for_log = body_json if body_json is not None else summarize_bytes(body_bytes)

        log.info(
            "REQ_ENTER rid=%s method=%s path=%s query=%s client=%s",
            rid, method, path, query, client,
        )
        log.debug("REQ_HEADERS rid=%s headers=%s", rid, headers)
        if body_bytes:
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
