"""Grant callback — POST status to configured callback URL."""

import json
import logging
from typing import Optional

import httpx

log = logging.getLogger("gateway.callbacks")


async def fire_grant_callback(
    grant: dict,
    status: str,
    expires_at: Optional[str] = None,
    *,
    requestor_name: str = "",
):
    """POST grant status to the requestor's configured callback URL."""
    from gateway.app import get_requestor_callback

    meta = json.loads(grant.get("metadata") or "{}")
    if meta.get("callback") is False:
        return

    # Look up per-requestor callback config
    cb_creds = get_requestor_callback(requestor_name)
    callback_url = cb_creds.get("url", "")
    if not callback_url:
        return

    payload: dict = {
        "grantId": grant["id"],
        "resourceType": grant.get("resource_type", "gmail"),
        "level": grant["level"],
        "status": status,
    }
    if expires_at:
        payload["expiresAt"] = expires_at
    if meta.get("callbackSessionKey"):
        payload["sessionKey"] = meta["callbackSessionKey"]

    headers: dict = {"Content-Type": "application/json"}
    if cb_creds.get("cf_auth") and cb_creds.get("cf_client_id"):
        headers["CF-Access-Client-Id"] = cb_creds["cf_client_id"]
        headers["CF-Access-Client-Secret"] = cb_creds["cf_client_secret"]
    if cb_creds.get("hooks_token"):
        headers["X-Gitlab-Token"] = cb_creds["hooks_token"]

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.post(callback_url, json=payload, headers=headers)
            if resp.status_code >= 400:
                log.error("Grant callback failed: %s %s", resp.status_code, resp.text)
            else:
                log.info("Grant callback sent to %s (status=%s)", callback_url, status)
        except Exception as e:
            log.error("Grant callback error: %s", e)
