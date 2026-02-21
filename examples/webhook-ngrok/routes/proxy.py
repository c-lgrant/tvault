import base64

import httpx
from fastapi import APIRouter, Request, Response

from auth import extract_auth_headers, verify_hmac, verify_ticket
from config import error_response, log
from crypto import decrypt_token_field, get_encryption_key
from middleware import safe_json_loads
from store import kv_store

router = APIRouter()


@router.post("/v1/proxy")
async def proxy(request: Request):
    """MCP Proxy endpoint — webhook injects credential into upstream request.

    TV forwards the agent's request here with a signed proxy ticket.
    The webhook decrypts the credential, injects it into the upstream
    request headers (replacing ${TOKEN}), makes the upstream call,
    and returns the response. TV never sees the credential.
    """
    rid, body_bytes, sig, ts, req_id = extract_auth_headers(request)
    log.info("proxy_enter rid=%s", rid)

    if body_bytes is None:
        body_bytes = await request.body()

    # Verify HMAC headers (authenticates TV)
    auth_err = verify_hmac(body_bytes, sig, ts, req_id, rid)
    if auth_err is not None:
        return auth_err

    data, err = safe_json_loads(body_bytes)
    if data is None:
        return error_response(400, "invalid_request", f"Invalid JSON: {err}")

    ticket = data.get("ticket", "")
    service = data.get("service", "")
    upstream = data.get("upstream", {})
    header_templates = data.get("headerTemplates", {})

    if not ticket or not service:
        return error_response(400, "invalid_request", "Missing 'ticket' or 'service'")
    if not upstream.get("url"):
        return error_response(400, "invalid_request", "Missing 'upstream.url'")

    # Verify ticket (authorizes the specific proxy operation)
    payload, ticket_err = verify_ticket(ticket, rid)
    if ticket_err is not None:
        return ticket_err

    if payload.get("pur") != "proxy":
        return error_response(401, "ticket_invalid", "Ticket purpose must be 'proxy'")
    if payload.get("svc") != service:
        return error_response(401, "ticket_invalid", f"Ticket is for service '{payload.get('svc')}', not '{service}'")

    # Decrypt the credential
    key = get_encryption_key()
    stored_doc = kv_store["tokens"].get(service)
    if not stored_doc:
        return error_response(404, "token_not_found", f"No token stored for service '{service}'")

    try:
        if "fields" in stored_doc:
            access_token = decrypt_token_field(key, stored_doc, "accessToken", rid)
        else:
            # Plaintext format (stored via backend /v1/storage)
            access_token = stored_doc.get("accessToken")
        if not access_token:
            return error_response(404, "token_not_found", f"No accessToken found for service '{service}'")
    except Exception as e:
        log.exception("proxy_decrypt_failed rid=%s", rid)
        return error_response(500, "internal_error", f"Credential decryption failed: {e}")

    # Build upstream request with credential injected
    upstream_url = upstream["url"]
    upstream_method = upstream.get("method", "GET").upper()
    upstream_headers = dict(upstream.get("headers", {}))
    upstream_body_b64 = upstream.get("body")
    upstream_body = base64.b64decode(upstream_body_b64) if upstream_body_b64 else None

    # Inject credential into header templates
    for header_name, template in header_templates.items():
        upstream_headers[header_name] = template.replace("${TOKEN}", access_token)

    log.info(
        "proxy_upstream rid=%s method=%s url=%s",
        rid, upstream_method, upstream_url,
    )

    # Make upstream request
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            upstream_resp = await client.request(
                method=upstream_method,
                url=upstream_url,
                headers=upstream_headers,
                content=upstream_body,
            )

        # Return upstream response
        resp_headers = {
            "X-Upstream-Status": str(upstream_resp.status_code),
        }

        log.info(
            "proxy_exit rid=%s upstream_status=%s",
            rid, upstream_resp.status_code,
        )

        return Response(
            content=upstream_resp.content,
            status_code=upstream_resp.status_code,
            headers=resp_headers,
            media_type=upstream_resp.headers.get("content-type", "application/json"),
        )

    except httpx.TimeoutException:
        return error_response(504, "upstream_timeout", "Upstream request timed out")
    except Exception as e:
        log.exception("proxy_upstream_failed rid=%s", rid)
        return error_response(502, "upstream_error", f"Upstream request failed: {e}")
