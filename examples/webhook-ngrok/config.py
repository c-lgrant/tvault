import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from cachetools import TTLCache
from fastapi.responses import JSONResponse

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

WEBHOOK_VERSION = "2.0.0"
CAPABILITIES = ["store", "credential", "proxy", "refresh", "storage"]

TIMESTAMP_TOLERANCE = 300  # 5 minutes
OAUTH_TIMEOUT = 10  # seconds
STORE_PATH = Path(os.environ.get("TOKENVAULT_STORE_PATH", "/data/tokenvault_store.json"))
KV_STORE_PATH = Path(os.environ.get("TOKENVAULT_KV_STORE_PATH", "/data/tokenvault_kv_store.json"))

# External URLs — required for registration flow
WEBHOOK_EXTERNAL_URL = os.environ.get("WEBHOOK_EXTERNAL_URL", "")
TOKENVAULT_FRONTEND_URL = os.environ.get("TOKENVAULT_FRONTEND_URL", "https://tokenvault.uk")

# Track seen request IDs to prevent replay (TTL = 10 min, max 10k entries)
seen_request_ids: TTLCache = TTLCache(maxsize=10_000, ttl=600)

# Track seen ticket nonces to prevent replay (TTL = 2 min, max 10k entries)
seen_ticket_nonces: TTLCache = TTLCache(maxsize=10_000, ttl=120)

# One-time registration codes (TTL = 5 min, max 100 entries)
registration_codes: TTLCache = TTLCache(maxsize=100, ttl=300)

# Track server start time for uptime reporting
start_time = time.time()


def error_response(status_code: int, error_code: str, message: str) -> JSONResponse:
    """Return a spec-compliant error response."""
    return JSONResponse(
        status_code=status_code,
        content={"error": error_code, "message": message},
    )


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
