"""Grant management routes — request, get, list, revoke.

The core create-or-reuse-a-grant logic lives at module level as
``create_or_reuse_grant`` so other routes (e.g. ``POST /api/ssh/credentials``)
can share it without an internal HTTP round-trip.
"""

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
from gateway.grants import find_active_ssh_grant, sanitize_grant
from gateway.models import GrantRequest
from gateway.providers import get_provider
from gateway.signal import send_signal_message

log = logging.getLogger("gateway.routes.grants")

# Rate limiting for grant requests — applied only when a NEW grant is actually
# being created, not on dedupe'd reuses.
_grant_request_times: deque = deque()


def _apply_rate_limit() -> None:
    """Raise HTTP 429 if we've seen too many new grant creates recently."""
    now_mono = time.monotonic()
    max_per_min = CONFIG.get("rate_limit", {}).get("grant_requests_per_minute", 5)
    while _grant_request_times and _grant_request_times[0] < now_mono - 60:
        _grant_request_times.popleft()
    if len(_grant_request_times) >= max_per_min:
        raise HTTPException(429, "Rate limit exceeded. Try again later.")
    _grant_request_times.append(now_mono)


async def create_or_reuse_grant(
    req: GrantRequest,
    requestor_name: str,
) -> dict:
    """Validate + dedupe + (create or reuse) a grant.

    Returns the HTTP response body. Raises ``HTTPException`` on validation
    failure or rate-limit. Applies the rate limit only when a fresh grant is
    actually being created (dedupe'd reuses do not consume the bucket).

    Used by both ``POST /api/grants/request`` and ``POST /api/ssh/credentials``
    (scope mode), so the dedupe rules live in exactly one place.
    """
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

    # ── SSH dedupe: reuse an active matching grant when possible ─────────
    # Unless the caller has explicitly asked for a new grant (because the
    # existing one is too short), return the active grant instead of
    # creating a new pending approval request.
    previous_grant_id: Optional[str] = None
    if req.resourceType == "ssh":
        match = find_active_ssh_grant(
            level=req.level,
            host=req.host,
            host_group=req.hostGroup,
            principal=req.principal,
            role=req.role,
            requestor=requestor_name,
            requested_duration_minutes=duration,
        )
        if match is not None:
            existing = match["grant"]
            if not req.allowReplaceShorterGrant:
                # Reuse the active grant — suppress the duplicate request.
                # No rate-limit charged: we didn't create anything.
                audit({
                    "action": "grant_request_deduped",
                    "grantId": existing["id"],
                    "resourceType": "ssh",
                    "level": req.level,
                    "requestor": requestor_name,
                    "durationSatisfied": match["duration_satisfied"],
                    "remainingSeconds": match["remaining_seconds"],
                    "requestedSeconds": match["requested_seconds"],
                })
                resp = {
                    "grantId": existing["id"],
                    "status": existing["status"],
                    "level": existing["level"],
                    "resourceType": "ssh",
                    "durationMinutes": existing["duration_minutes"],
                    "action": "reused_active_grant",
                    "reused": True,
                    "durationSatisfied": match["duration_satisfied"],
                    "shorterThanRequested": match["shorter_than_requested"],
                    "requestedDurationSeconds": match["requested_seconds"],
                    "remainingDurationSeconds": match["remaining_seconds"],
                    "expiresAt": existing.get("expires_at"),
                }
                if match["shorter_than_requested"]:
                    resp["message"] = (
                        "Reused active SSH grant, but remaining duration is "
                        "shorter than requested. Set "
                        "allowReplaceShorterGrant=true to request a new "
                        "longer grant."
                    )
                else:
                    resp["message"] = "Reused active SSH grant."
                return resp
            else:
                # Caller explicitly asked for a new longer grant. Proceed
                # with a fresh approval request, but record the linkage so
                # the response/audit trail explain why.
                previous_grant_id = existing["id"]

    # ── About to actually create a new grant — apply the rate limit now ─
    _apply_rate_limit()

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
        "previousGrantId": previous_grant_id,
        "replacementReason": (
            "insufficient_remaining_duration" if previous_grant_id else None
        ),
    })

    resp: dict = {
        "grantId": grant_id,
        "status": "pending",
        "level": req.level,
        "resourceType": req.resourceType,
        "durationMinutes": duration,
        "action": (
            "requested_replacement_grant_due_to_short_duration"
            if previous_grant_id
            else "requested_new_grant"
        ),
        "reused": False,
        "message": f"Approval request sent. Poll GET /api/grants/{grant_id} for status.",
    }
    if previous_grant_id:
        resp["previousGrantId"] = previous_grant_id
        resp["replacementRequested"] = True
        resp["durationSatisfied"] = False
    return resp


def register(app: FastAPI, *, fire_callback):

    @app.post("/api/grants/request")
    async def request_grant(req: GrantRequest, request: Request):
        """Request elevated access. Sends approval via Signal (link + reply code)."""
        requestor_name = getattr(request.state, "requestor_name", None) or CONFIG.get("agent_name", "Agent")
        return await create_or_reuse_grant(req, requestor_name)

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
