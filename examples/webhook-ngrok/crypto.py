import base64
import os
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from config import log
from store import store


def get_encryption_key() -> bytes:
    """Get the webhook's own encryption key."""
    key = store.get("encryption_key")
    if key is None:
        raise ValueError("No encryption key: webhook not configured")
    return key


def decrypt(key: bytes, ciphertext_b64: str, rid: str) -> str:
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


def encrypt(key: bytes, plaintext: str, rid: str) -> str:
    iv = os.urandom(12)
    ct_with_tag = AESGCM(key).encrypt(iv, plaintext.encode("utf-8"), None)
    out = base64.b64encode(iv + ct_with_tag).decode("ascii")
    log.info("encrypt rid=%s plaintext_len=%s out_len=%s", rid, len(plaintext), len(out))
    return out


def decrypt_token_field(key: bytes, encrypted_doc: dict, field: str, rid: str) -> Optional[str]:
    """Decrypt a field from an encrypted token document's 'fields' dict."""
    fields = encrypted_doc.get("fields", {})
    encrypted_value = fields.get(field)
    if not encrypted_value:
        return None
    return decrypt(key, encrypted_value, rid)


def build_encrypted_token_document(
    key: bytes,
    access_token: Optional[str],
    refresh_token: Optional[str],
    meta: dict,
    rid: str,
    extra_sensitive: Optional[dict] = None,
) -> dict:
    """Build a spec-compliant encrypted token document.

    Args:
        extra_sensitive: Additional sensitive fields to encrypt (e.g.
            certificateData, privateKeyData, sshPrivateKey).
    """
    fields = {}
    if access_token is not None:
        fields["accessToken"] = encrypt(key, access_token, rid)
    if refresh_token is not None:
        fields["refreshToken"] = encrypt(key, refresh_token, rid)

    # Encrypt any additional sensitive fields (cert/SSH data)
    if extra_sensitive:
        for field_name, value in extra_sensitive.items():
            if value is not None:
                fields[field_name] = encrypt(key, str(value), rid)

    # Ensure capability flags are set in meta
    if "hasRefreshToken" not in meta:
        meta["hasRefreshToken"] = refresh_token is not None and len(str(refresh_token)) > 0
    meta["hasCertificate"] = "certificateData" in fields
    meta["hasPrivateKey"] = "privateKeyData" in fields
    meta["hasSSHKey"] = "sshPrivateKey" in fields

    return {
        "v": 1,
        "alg": "AES-256-GCM",
        "fields": fields,
        "meta": meta,
    }
