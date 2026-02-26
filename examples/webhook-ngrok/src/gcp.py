"""GCP Service Account → short-lived access token minting.

When a stored credential is a GCP service account JSON key, this module
mints a short-lived OAuth2 access token (~1 hour) instead of returning
the raw key. The agent never sees the SA private key.

Flow:
  1. Agent requests credential via Token Vault
  2. TV validates API key, policies, grants → 307 redirect to webhook
  3. Webhook decrypts stored SA JSON
  4. This module detects it's a SA key and mints an access token
  5. Agent receives only the short-lived access token
"""

import json
import time
from typing import Optional

from cachetools import TTLCache
from google.auth.transport.requests import Request as GoogleAuthRequest
from google.oauth2 import service_account

from config import log

# Cache minted tokens: key = (service_name, scopes_tuple) → (access_token, expiry)
# TTL 50 min (tokens last 60 min, mint fresh 10 min before expiry)
_token_cache: TTLCache = TTLCache(maxsize=100, ttl=3000)

# Default scopes when none specified
DEFAULT_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]


def is_gcp_service_account(credential_value: str) -> bool:
    """Check if a decrypted credential looks like a GCP SA JSON key."""
    try:
        data = json.loads(credential_value)
        return (
            isinstance(data, dict)
            and data.get("type") == "service_account"
            and "private_key" in data
            and "client_email" in data
        )
    except (json.JSONDecodeError, TypeError, ValueError):
        return False


def mint_access_token(
    credential_value: str,
    service_name: str,
    scopes: Optional[list[str]] = None,
    rid: str = "",
) -> dict:
    """Mint a short-lived GCP access token from a service account JSON key.

    Args:
        credential_value: The decrypted SA JSON string.
        service_name: Token Vault service name (for cache key + logging).
        scopes: OAuth2 scopes to request. Defaults to cloud-platform.
        rid: Request ID for logging.

    Returns:
        Dict with accessToken, expiresAt (ISO), tokenType, serviceAccount.
    """
    scopes = scopes or DEFAULT_SCOPES
    cache_key = (service_name, tuple(sorted(scopes)))

    # Check cache first
    cached = _token_cache.get(cache_key)
    if cached:
        token, expiry_iso, email = cached
        log.info(
            "gcp_mint_cache_hit rid=%s service=%s email=%s",
            rid, service_name, email,
        )
        return {
            "accessToken": token,
            "expiresAt": expiry_iso,
            "tokenType": "Bearer",
            "serviceAccount": email,
            "source": "cache",
        }

    # Parse SA JSON and mint
    sa_info = json.loads(credential_value)
    email = sa_info.get("client_email", "unknown")

    log.info(
        "gcp_mint_start rid=%s service=%s email=%s scopes=%s",
        rid, service_name, email, scopes,
    )

    credentials = service_account.Credentials.from_service_account_info(
        sa_info, scopes=scopes,
    )
    credentials.refresh(GoogleAuthRequest())

    access_token = credentials.token
    expiry = credentials.expiry  # datetime in UTC

    if expiry:
        expiry_iso = expiry.isoformat() + "Z"
        expiry_ms = int(expiry.timestamp() * 1000)
    else:
        # Fallback: assume 1 hour from now
        expiry_iso = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 3600)
        )
        expiry_ms = int((time.time() + 3600) * 1000)

    # Cache the minted token
    _token_cache[cache_key] = (access_token, expiry_iso, email)

    log.info(
        "gcp_mint_ok rid=%s service=%s email=%s expires=%s",
        rid, service_name, email, expiry_iso,
    )

    return {
        "accessToken": access_token,
        "expiresAt": expiry_iso,
        "expiryTime": expiry_ms,
        "tokenType": "Bearer",
        "serviceAccount": email,
        "source": "minted",
    }
