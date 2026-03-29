"""Grant callback — POST status to configured callback URL."""

import json
import logging
from typing import Optional

import httpx

from gateway.config import CONFIG

log = logging.getLogger("gateway.callbacks")


async def fire_grant_callback(
    grant: dict,
    status: str,
    expires_at: Optional[str] = None,
    *,
    cf_client_id: str = "",
    cf_client_secret: str = "",
    hooks_token: str = "",
):
    """POST grant status to the configured callback URL."""
    callback_cfg = CONFIG.get("callback", {})
    callback_url = callback_cfg.get("url", "")
    if not callback_url:
        return

    meta = json.loads(grant.get("metadata") or "{}")
    if meta.get("callback") is False:
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
    if callback_cfg.get("cf_auth") and cf_client_id:
        headers["CF-Access-Client-Id"] = cf_client_id
        headers["CF-Access-Client-Secret"] = cf_client_secret
    if hooks_token:
        headers["X-Gitlab-Token"] = hooks_token

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.post(callback_url, json=payload, headers=headers)
            if resp.status_code >= 400:
                log.error("Grant callback failed: %s %s", resp.status_code, resp.text)
            else:
                log.info("Grant callback sent to %s (status=%s)", callback_url, status)
        except Exception as e:
            log.error("Grant callback error: %s", e)
