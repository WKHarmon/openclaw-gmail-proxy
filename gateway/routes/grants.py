"""Grant management routes — request, get, list, revoke."""

import asyncio
import json
import logging
import secrets
import time
from collections import deque
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, Request

from gateway.audit import audit
from gateway.config import CONFIG, MAX_GRANT_DURATION_MINUTES
from gateway.db import db_conn
from gateway.grants import sanitize_grant
from gateway.models import GrantRequest
from gateway.providers import get_provider
from gateway.signal import send_signal_message

log = logging.getLogger("gateway.routes.grants")

# Rate limiting for grant requests
_grant_request_times: deque = deque()


def register(app: FastAPI, *, fire_callback):

    @app.post("/api/grants/request")
    async def request_grant(req: GrantRequest, request: Request):
        """Request elevated access. Sends approval via Signal (link + reply code)."""
        requestor_name = getattr(request.state, "requestor_name", None) or CONFIG.get("agent_name", "Agent")
        # Rate limiting
        now_mono = time.monotonic()
        max_per_min = CONFIG.get("rate_limit", {}).get("grant_requests_per_minute", 5)
        while _grant_request_times and _grant_request_times[0] < now_mono - 60:
            _grant_request_times.popleft()
        if len(_grant_request_times) >= max_per_min:
            raise HTTPException(429, "Rate limit exceeded. Try again later.")
        _grant_request_times.append(now_mono)

        # Look up provider
        provider = get_provider(req.resourceType)
        if not provider:
            raise HTTPException(400, f"Unknown resource type: {req.resourceType}")

        # Build provider-specific params dict from the request
        params = req.model_dump(exclude={"resourceType", "level", "description",
                                         "durationMinutes", "callback", "callbackSessionKey"})

        # Validate with provider
        error = provider.validate_request(req.level, params)
        if error:
            raise HTTPException(400, error)

        # Determine duration
        default_dur = provider.default_duration(req.level)
        duration = min(req.durationMinutes or default_dur, MAX_GRANT_DURATION_MINUTES)

        grant_id = f"g_{secrets.token_hex(8)}"
        approval_token = secrets.token_urlsafe(32)
        signal_code = secrets.token_hex(3).upper()
        now = datetime.now(timezone.utc)

        # Build metadata (shared across providers)
        meta_dict: dict = {
            "callback": req.callback,
            "callbackSessionKey": req.callbackSessionKey,
        }

        # Gmail-specific: fetch message metadata for L1 notifications
        if req.resourceType == "gmail" and req.messageId:
            try:
                from gateway.providers.gmail import extract_metadata, get_gmail_service
                service = await asyncio.to_thread(get_gmail_service)
                msg = await asyncio.to_thread(
                    lambda: service.users().messages().get(
                        userId="me",
                        id=req.messageId,
                        format="metadata",
                        metadataHeaders=["From", "Subject"],
                    ).execute()
                )
                meta = extract_metadata(msg)
                meta_dict["subject"] = meta.get("subject", "")
                meta_dict["sender"] = meta.get("from", "")
            except Exception as e:
                log.warning("Could not fetch message metadata for grant request: %s", e)

        # Build resource_params JSON (provider-specific structured data)
        resource_params = {}
        if req.resourceType == "ssh":
            for key in ("host", "principal", "hostGroup", "role", "publicKey"):
                val = getattr(req, key, None)
                if val is not None:
                    resource_params[key] = val

        conn = db_conn()
        try:
            conn.execute(
                "INSERT INTO grants "
                "(id, level, status, message_id, query, description, "
                "approval_token, signal_code, created_at, duration_minutes, "
                "metadata, resource_type, resource_params, requestor) "
                "VALUES (?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    grant_id,
                    req.level,
                    req.messageId,
                    req.query,
                    req.description,
                    approval_token,
                    signal_code,
                    now.isoformat(),
                    duration,
                    json.dumps(meta_dict),
                    req.resourceType,
                    json.dumps(resource_params) if resource_params else None,
                    requestor_name,
                ),
            )
            conn.commit()
        finally:
            conn.close()

        # Build the grant dict for formatting
        grant_for_format = {
            "id": grant_id,
            "level": req.level,
            "description": req.description,
            "signal_code": signal_code,
            "duration_minutes": duration,
            "metadata": json.dumps(meta_dict),
            "resource_type": req.resourceType,
            "resource_params": json.dumps(resource_params) if resource_params else None,
            "query": req.query,
            "requestor": requestor_name,
        }

        approval_url = f"{CONFIG['approval_url_base']}/approve/{approval_token}"
        signal_msg = provider.format_signal_notification(grant_for_format, approval_url)
        await send_signal_message(signal_msg)

        audit({
            "action": "grant_requested",
            "grantId": grant_id,
            "resourceType": req.resourceType,
            "level": req.level,
            "messageId": req.messageId,
            "query": req.query,
            "description": req.description,
            "durationMinutes": duration,
            "status": "pending",
            "requestor": requestor_name,
        })

        return {
            "grantId": grant_id,
            "status": "pending",
            "level": req.level,
            "resourceType": req.resourceType,
            "durationMinutes": duration,
            "message": f"Approval request sent. Poll GET /api/grants/{grant_id} for status.",
        }

    @app.get("/api/grants/active")
    async def list_active_grants(resourceType: Optional[str] = None):
        now = datetime.now(timezone.utc).isoformat()
        conn = db_conn()
        try:
            if resourceType:
                rows = conn.execute(
                    "SELECT * FROM grants WHERE status='active' "
                    "AND resource_type=? AND (expires_at IS NULL OR expires_at>?)",
                    (resourceType, now),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM grants WHERE status='active' "
                    "AND (expires_at IS NULL OR expires_at>?)",
                    (now,),
                ).fetchall()
        finally:
            conn.close()
        return {"grants": [sanitize_grant(dict(r)) for r in rows]}

    @app.get("/api/grants/{grant_id}")
    async def get_grant(grant_id: str):
        conn = db_conn()
        try:
            row = conn.execute("SELECT * FROM grants WHERE id=?", (grant_id,)).fetchone()
        finally:
            conn.close()
        if not row:
            raise HTTPException(404, "Grant not found")
        return sanitize_grant(dict(row))

    @app.delete("/api/grants/{grant_id}")
    async def revoke_grant(grant_id: str):
        conn = db_conn()
        try:
            row = conn.execute("SELECT * FROM grants WHERE id=?", (grant_id,)).fetchone()
            if not row:
                raise HTTPException(404, "Grant not found")
            conn.execute("UPDATE grants SET status='revoked' WHERE id=?", (grant_id,))
            conn.commit()
        finally:
            conn.close()
        audit({"action": "grant_revoked", "grantId": grant_id})
        return {"grantId": grant_id, "status": "revoked"}
