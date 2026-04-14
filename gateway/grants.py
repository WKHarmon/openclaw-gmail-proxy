"""Grant lifecycle — activate, deny, sanitize, query helpers."""

import json
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


def _ssh_scope_matches(grant_params: dict, level: int, host: Optional[str],
                       host_group: Optional[str], principal: Optional[str],
                       role: Optional[str]) -> bool:
    """Decide whether an existing SSH grant's scope covers a new request.

    Uses narrow equivalence: same level, same host (L1), same host_group (L2),
    same principal, and same role (if the caller explicitly asked for one).
    This preserves security semantics — never broaden access by matching loosely.
    """
    if grant_params.get("principal") != principal:
        return False
    # If the caller explicitly specified a role, require equality.
    # If the caller didn't specify a role, any role on the existing grant is
    # acceptable (defaults to the host/group config on the existing grant).
    if role is not None and grant_params.get("role") != role:
        return False
    if level == 1:
        return grant_params.get("host") == host and not grant_params.get("hostGroup")
    if level == 2:
        return grant_params.get("hostGroup") == host_group and not grant_params.get("host")
    if level == 3:
        # Level 3 is principal-scoped only (no host/host_group constraint).
        return not grant_params.get("host") and not grant_params.get("hostGroup")
    return False


def _remaining_seconds(grant: dict, now: Optional[datetime] = None) -> int:
    """Seconds remaining before grant's expires_at. 0 if no expires_at."""
    if not grant.get("expires_at"):
        return 0
    now = now or datetime.now(timezone.utc)
    try:
        exp = datetime.fromisoformat(grant["expires_at"])
    except (TypeError, ValueError):
        return 0
    return max(0, int((exp - now).total_seconds()))


def find_active_ssh_grant(
    *,
    level: int,
    host: Optional[str] = None,
    host_group: Optional[str] = None,
    principal: Optional[str] = None,
    role: Optional[str] = None,
    requestor: Optional[str] = None,
    requested_duration_minutes: Optional[int] = None,
) -> Optional[dict]:
    """Find a reusable active SSH grant for the given scope.

    Returns a dict:
      {
        "grant": <full grant row>,
        "remaining_seconds": int,
        "requested_seconds": int | None,
        "duration_satisfied": bool,
        "shorter_than_requested": bool,
      }
    or None if no matching active SSH grant exists.

    Matches narrowly on (level, host/host_group, principal, role, requestor)
    to avoid broadening access.
    """
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    conn = db_conn()
    try:
        query = (
            "SELECT * FROM grants WHERE status='active' AND resource_type='ssh' "
            "AND level=? AND expires_at>?"
        )
        params: list = [level, now_iso]
        if requestor is not None:
            query += " AND requestor=?"
            params.append(requestor)
        query += " ORDER BY expires_at DESC"
        rows = conn.execute(query, tuple(params)).fetchall()
    finally:
        conn.close()

    best = None
    best_remaining = -1
    for r in rows:
        g = dict(r)
        try:
            g_params = json.loads(g.get("resource_params") or "{}")
        except json.JSONDecodeError:
            continue
        if not _ssh_scope_matches(g_params, level, host, host_group, principal, role):
            continue
        remaining = _remaining_seconds(g, now)
        if remaining > best_remaining:
            best = g
            best_remaining = remaining

    if best is None:
        return None

    requested_seconds = (
        requested_duration_minutes * 60
        if requested_duration_minutes is not None
        else None
    )
    satisfied = (
        requested_seconds is None or best_remaining >= requested_seconds
    )
    return {
        "grant": best,
        "remaining_seconds": best_remaining,
        "requested_seconds": requested_seconds,
        "duration_satisfied": satisfied,
        "shorter_than_requested": not satisfied,
    }
