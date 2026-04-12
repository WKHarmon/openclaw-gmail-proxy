"""Approval web UI — GET/POST /approve/:token."""

import hmac
import json
import logging
import secrets
import time

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from html import escape

from gateway.config import CONFIG
from gateway.db import db_conn
from gateway.grants import activate_grant, deny_grant
from gateway.providers import get_provider

log = logging.getLogger("gateway.routes.approval")

# CSRF tokens: approval_token -> (csrf_token, expiry_monotonic)
_csrf_tokens: dict[str, tuple[str, float]] = {}

APPROVAL_PAGE_CSS = """
body { font-family: system-ui, -apple-system, sans-serif; max-width: 600px;
       margin: 40px auto; padding: 0 20px; background: #fafafa; color: #222; }
.card { border: 1px solid #ddd; border-radius: 8px; padding: 20px;
        margin: 20px 0; background: #fff; }
.btn { display: inline-block; padding: 14px 36px; border: none;
       border-radius: 6px; font-size: 1.1em; cursor: pointer;
       margin: 8px; color: #fff; text-decoration: none; }
.approve { background: #22c55e; } .approve:hover { background: #16a34a; }
.deny { background: #ef4444; } .deny:hover { background: #dc2626; }
code { background: #f3f4f6; padding: 2px 6px; border-radius: 4px; }
.status { font-size: 1.4em; margin: 20px 0; }
"""


def _approval_html(title: str, body: str) -> str:
    return (
        "<!DOCTYPE html><html><head>"
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{title}</title><style>{APPROVAL_PAGE_CSS}</style>"
        f"</head><body>{body}</body></html>"
    )


def _issue_csrf_token(approval_token: str) -> str:
    now_mono = time.monotonic()
    expired_keys = [k for k, (_, exp) in _csrf_tokens.items() if exp < now_mono]
    for k in expired_keys:
        _csrf_tokens.pop(k, None)

    csrf_token = secrets.token_urlsafe(32)
    _csrf_tokens[approval_token] = (csrf_token, now_mono + 600)
    return csrf_token


def _validate_csrf_token(approval_token: str, csrf_token: str) -> bool:
    stored = _csrf_tokens.pop(approval_token, None)
    if not stored:
        return False
    expected, expiry = stored
    if time.monotonic() > expiry:
        return False
    return hmac.compare_digest(csrf_token, expected)


def register(app: FastAPI, *, fire_callback):

    @app.get("/approve/{token}", response_class=HTMLResponse)
    async def approval_page(token: str):
        conn = db_conn()
        try:
            row = conn.execute(
                "SELECT * FROM grants WHERE approval_token=?", (token,)
            ).fetchone()
        finally:
            conn.close()

        if not row:
            return HTMLResponse(
                _approval_html("Not Found", "<h1>Invalid or expired approval link</h1>"),
                status_code=404,
            )

        grant = dict(row)

        if grant["status"] != "pending":
            label = {
                "active": "Already approved",
                "denied": "Denied",
                "expired": "Expired",
                "revoked": "Revoked",
                "consumed": "Already used",
            }.get(grant["status"], grant["status"])
            return HTMLResponse(
                _approval_html(
                    "Access Request",
                    f'<h1>Access Request</h1><div class="status">{label}</div>',
                )
            )

        agent_name = grant.get("requestor") or CONFIG.get("agent_name", "Agent")
        csrf_token = _issue_csrf_token(token)

        # Get provider-specific details
        resource_type = grant.get("resource_type", "gmail")
        provider = get_provider(resource_type)
        if provider:
            details = provider.format_approval_details(grant)
        else:
            details = f"<p><strong>Description:</strong> {escape(grant.get('description', ''))}</p>"

        body = (
            f"<h1>Access Request</h1>"
            f'<div class="card">'
            f"<p><strong>{escape(resource_type.upper())} Level {grant['level']}</strong>"
            f" — Requested by {escape(agent_name)}</p>"
            f"{details}</div>"
            f'<form method="POST" style="margin:20px 0;">'
            f'<input type="hidden" name="csrf_token" value="{csrf_token}">'
            f'<button type="submit" name="action" value="approve" class="btn approve">Approve</button>'
            f'<button type="submit" name="action" value="deny" class="btn deny">Deny</button>'
            f"</form>"
        )

        return HTMLResponse(_approval_html("Approve Access?", body))

    @app.post("/approve/{token}")
    async def handle_approval(token: str, request: Request):
        form = await request.form()
        action = form.get("action", "deny")
        csrf_token = form.get("csrf_token", "")

        if not _validate_csrf_token(token, csrf_token):
            return HTMLResponse(
                _approval_html("Error", "<h1>Invalid or expired form submission</h1>"
                               "<p>Please go back and reload the approval page.</p>"),
                status_code=403,
            )

        conn = db_conn()
        try:
            row = conn.execute(
                "SELECT * FROM grants WHERE approval_token=?", (token,)
            ).fetchone()
        finally:
            conn.close()

        if not row:
            return HTMLResponse(
                _approval_html("Not Found", "<h1>Invalid or expired approval link</h1>"),
                status_code=404,
            )

        grant = dict(row)

        if grant["status"] != "pending":
            return HTMLResponse(
                _approval_html(
                    "Access Request",
                    f"<h1>This request has already been {escape(grant['status'])}</h1>",
                )
            )

        if action == "approve":
            expires_at = activate_grant(grant, via="url")
            result_body = (
                f"<h1>Approved</h1>"
                f"<p>Access granted for {grant['duration_minutes']} minutes.</p>"
                f"<p>Expires: {expires_at.strftime('%H:%M UTC')}</p>"
            )
            await fire_callback(grant, "active", expires_at.isoformat())
        else:
            deny_grant(grant, via="url")
            result_body = "<h1>Denied</h1><p>Access request has been denied.</p>"
            await fire_callback(grant, "denied")

        return HTMLResponse(_approval_html("Access Request", result_body))
