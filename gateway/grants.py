"""Grant lifecycle — activate, deny, sanitize, query helpers."""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from gateway.audit import audit
from gateway.db import db_conn

log = logging.getLogger("gateway.grants")

GRANT_PUBLIC_FIELDS = (
    "id", "level", "status", "message_id", "query", "description",
    "created_at", "approved_at", "expires_at", "duration_minutes",
    "resource_type", "requestor",
)


def sanitize_grant(row: dict) -> dict:
    """Strip sensitive fields before returning to callers."""
    return {k: row[k] for k in GRANT_PUBLIC_FIELDS if k in row}


def activate_grant(grant: dict, via: str = "url") -> datetime:
    """Activate a pending grant. Returns expiry time."""
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=grant["duration_minutes"])
    conn = db_conn()
    try:
        conn.execute(
            "UPDATE grants SET status='active', approved_at=?, expires_at=? WHERE id=?",
            (now.isoformat(), expires_at.isoformat(), grant["id"]),
        )
        conn.commit()
    finally:
        conn.close()
    audit({
        "action": "grant_approved",
        "grantId": grant["id"],
        "resourceType": grant.get("resource_type", "gmail"),
        "level": grant["level"],
        "expiresAt": expires_at.isoformat(),
        "approvedVia": via,
        "requestor": grant.get("requestor"),
    })
    return expires_at


def deny_grant(grant: dict, via: str = "url"):
    """Deny a pending grant."""
    conn = db_conn()
    try:
        conn.execute("UPDATE grants SET status='denied' WHERE id=?", (grant["id"],))
        conn.commit()
    finally:
        conn.close()
    audit({
        "action": "grant_denied",
        "grantId": grant["id"],
        "resourceType": grant.get("resource_type", "gmail"),
        "level": grant["level"],
        "deniedVia": via,
        "requestor": grant.get("requestor"),
    })


def get_grant_by_id(grant_id: str) -> Optional[dict]:
    """Fetch a grant by ID."""
    conn = db_conn()
    try:
        row = conn.execute("SELECT * FROM grants WHERE id=?", (grant_id,)).fetchone()
    finally:
        conn.close()
    return dict(row) if row else None


def get_active_grant(grant_id: str) -> Optional[dict]:
    """Fetch a grant by ID if it is active and not expired."""
    now = datetime.now(timezone.utc).isoformat()
    conn = db_conn()
    try:
        row = conn.execute(
            "SELECT * FROM grants WHERE id=? AND status='active' AND expires_at>?",
            (grant_id, now),
        ).fetchone()
    finally:
        conn.close()
    return dict(row) if row else None
