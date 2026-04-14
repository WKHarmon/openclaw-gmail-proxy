"""Tests for the SSH grant dedupe / reuse behavior.

These tests cover:

  1. Existing matching active SSH grant, remaining duration satisfies request
  2. Existing matching active SSH grant, too short (reuse + shortfall flags)
  3. Existing matching active SSH grant but caller opts into replacement
  4. No matching active SSH grant -> normal new request
  5. Non-matching active grants don't get reused (host / principal / level /
     requestor differences)
  6. Backward-compat: old-style request payloads still work
"""

from __future__ import annotations

from conftest import HEADERS  # noqa: E402


# ── Test 1: active matching grant, duration satisfied ──────────────────────


def test_reuse_active_grant_when_duration_satisfied(gateway_env):
    gateway_env["insert_active_ssh_grant"](
        grant_id="g_active_long",
        level=1,
        host="server",
        principal="kyle",
        remaining_minutes=25,
        requestor="Lisa",
    )
    resp = gateway_env["client"].post(
        "/api/grants/request",
        headers=HEADERS,
        json={
            "resourceType": "ssh",
            "level": 1,
            "host": "server",
            "principal": "kyle",
            "description": "deploy",
            "durationMinutes": 15,
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["action"] == "reused_active_grant"
    assert body["reused"] is True
    assert body["grantId"] == "g_active_long"
    assert body["status"] == "active"
    assert body["durationSatisfied"] is True
    assert body["shorterThanRequested"] is False

    # Confirm NO new grant was created — still just the one we pre-seeded.
    conn = gateway_env["db_conn"]()
    try:
        count = conn.execute("SELECT COUNT(*) FROM grants").fetchone()[0]
    finally:
        conn.close()
    assert count == 1


# ── Test 2: active matching grant, too short ────────────────────────────────


def test_reuse_active_grant_when_shorter_than_requested(gateway_env):
    gateway_env["insert_active_ssh_grant"](
        grant_id="g_short",
        level=1,
        host="server",
        principal="kyle",
        remaining_minutes=2,
        requestor="Lisa",
    )
    resp = gateway_env["client"].post(
        "/api/grants/request",
        headers=HEADERS,
        json={
            "resourceType": "ssh",
            "level": 1,
            "host": "server",
            "principal": "kyle",
            "description": "deploy",
            "durationMinutes": 60,
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["action"] == "reused_active_grant"
    assert body["reused"] is True
    assert body["grantId"] == "g_short"
    assert body["durationSatisfied"] is False
    assert body["shorterThanRequested"] is True
    assert body["requestedDurationSeconds"] == 60 * 60
    # remaining should be ~2 minutes (a little less by test-runtime)
    assert 0 < body["remainingDurationSeconds"] <= 2 * 60
    assert "shorter than requested" in body["message"].lower()

    # No new grant created
    conn = gateway_env["db_conn"]()
    try:
        count = conn.execute("SELECT COUNT(*) FROM grants").fetchone()[0]
    finally:
        conn.close()
    assert count == 1


# ── Test 3: explicit replacement when existing grant is too short ──────────


def test_explicit_replacement_forces_new_grant(gateway_env):
    gateway_env["insert_active_ssh_grant"](
        grant_id="g_tiny",
        level=1,
        host="server",
        principal="kyle",
        remaining_minutes=1,
        requestor="Lisa",
    )
    resp = gateway_env["client"].post(
        "/api/grants/request",
        headers=HEADERS,
        json={
            "resourceType": "ssh",
            "level": 1,
            "host": "server",
            "principal": "kyle",
            "description": "longer deploy window",
            "durationMinutes": 120,
            "allowReplaceShorterGrant": True,
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["action"] == "requested_replacement_grant_due_to_short_duration"
    assert body["reused"] is False
    assert body["status"] == "pending"
    assert body["previousGrantId"] == "g_tiny"
    assert body["replacementRequested"] is True
    assert body["durationSatisfied"] is False
    # A new (pending) grant should have been persisted alongside the old one.
    assert body["grantId"] != "g_tiny"

    conn = gateway_env["db_conn"]()
    try:
        rows = conn.execute(
            "SELECT id, status FROM grants ORDER BY id"
        ).fetchall()
    finally:
        conn.close()
    statuses = {r["id"]: r["status"] for r in rows}
    assert statuses["g_tiny"] == "active"
    assert statuses[body["grantId"]] == "pending"


# ── Test 4: no matching active grant -> new request ────────────────────────


def test_no_match_creates_new_pending_grant(gateway_env):
    resp = gateway_env["client"].post(
        "/api/grants/request",
        headers=HEADERS,
        json={
            "resourceType": "ssh",
            "level": 1,
            "host": "server",
            "principal": "kyle",
            "description": "first access",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["action"] == "requested_new_grant"
    assert body["reused"] is False
    assert body["status"] == "pending"
    assert body["grantId"].startswith("g_")
    assert "previousGrantId" not in body


# ── Test 5: non-matching active grants are NOT reused ──────────────────────


def test_different_host_does_not_reuse(gateway_env):
    gateway_env["insert_active_ssh_grant"](
        grant_id="g_other_host",
        level=1,
        host="aiserver",
        principal="kyle",
        remaining_minutes=25,
        requestor="Lisa",
    )
    resp = gateway_env["client"].post(
        "/api/grants/request",
        headers=HEADERS,
        json={
            "resourceType": "ssh",
            "level": 1,
            "host": "server",
            "principal": "kyle",
            "description": "deploy to server",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["action"] == "requested_new_grant"
    assert body["reused"] is False
    assert body["status"] == "pending"
    assert body["grantId"] != "g_other_host"


def test_different_principal_does_not_reuse(gateway_env):
    gateway_env["insert_active_ssh_grant"](
        grant_id="g_other_principal",
        level=1,
        host="server",
        principal="root",
        remaining_minutes=25,
        requestor="Lisa",
    )
    resp = gateway_env["client"].post(
        "/api/grants/request",
        headers=HEADERS,
        json={
            "resourceType": "ssh",
            "level": 1,
            "host": "server",
            "principal": "kyle",
            "description": "deploy to server as kyle",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["action"] == "requested_new_grant"
    assert body["reused"] is False


def test_different_level_does_not_reuse(gateway_env):
    # Level-3 principal-only grant should not be auto-reused for a Level-1
    # host-scoped request (the scope is different, even though principal
    # matches).
    gateway_env["insert_active_ssh_grant"](
        grant_id="g_level3",
        level=3,
        principal="kyle",
        remaining_minutes=25,
        requestor="Lisa",
    )
    resp = gateway_env["client"].post(
        "/api/grants/request",
        headers=HEADERS,
        json={
            "resourceType": "ssh",
            "level": 1,
            "host": "server",
            "principal": "kyle",
            "description": "deploy to server",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["action"] == "requested_new_grant"
    assert body["reused"] is False


def test_different_requestor_does_not_reuse(gateway_env):
    # Agent A's grant should not satisfy Agent B's request.
    gateway_env["insert_active_ssh_grant"](
        grant_id="g_other_agent",
        level=1,
        host="server",
        principal="kyle",
        remaining_minutes=25,
        requestor="OtherAgent",
    )
    resp = gateway_env["client"].post(
        "/api/grants/request",
        headers=HEADERS,
        json={
            "resourceType": "ssh",
            "level": 1,
            "host": "server",
            "principal": "kyle",
            "description": "deploy",
        },
    )
    # Default agent_name from config is "Lisa"; the route will use that as
    # the requestor when no api-key middleware has set request.state.
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["action"] == "requested_new_grant"
    assert body["reused"] is False


# ── Test 6: Level 2 host group reuse ───────────────────────────────────────


def test_reuse_active_level2_group_grant(gateway_env):
    gateway_env["insert_active_ssh_grant"](
        grant_id="g_group",
        level=2,
        host_group="production",
        principal="deploy",
        remaining_minutes=25,
        requestor="Lisa",
    )
    resp = gateway_env["client"].post(
        "/api/grants/request",
        headers=HEADERS,
        json={
            "resourceType": "ssh",
            "level": 2,
            "hostGroup": "production",
            "principal": "deploy",
            "description": "rolling restart",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["action"] == "reused_active_grant"
    assert body["grantId"] == "g_group"


# ── Test 7: find_active_ssh_grant helper directly ──────────────────────────


def test_find_active_ssh_grant_helper(gateway_env):
    from gateway.grants import find_active_ssh_grant

    gateway_env["insert_active_ssh_grant"](
        grant_id="g_helper",
        level=1,
        host="server",
        principal="kyle",
        remaining_minutes=10,
        requestor="Lisa",
    )
    match = find_active_ssh_grant(
        level=1,
        host="server",
        principal="kyle",
        requestor="Lisa",
        requested_duration_minutes=5,
    )
    assert match is not None
    assert match["grant"]["id"] == "g_helper"
    assert match["duration_satisfied"] is True
    assert match["shorter_than_requested"] is False

    # Shorter remaining than asked
    match2 = find_active_ssh_grant(
        level=1,
        host="server",
        principal="kyle",
        requestor="Lisa",
        requested_duration_minutes=60,
    )
    assert match2 is not None
    assert match2["duration_satisfied"] is False
    assert match2["shorter_than_requested"] is True

    # No match (different host)
    assert find_active_ssh_grant(
        level=1,
        host="aiserver",
        principal="kyle",
        requestor="Lisa",
    ) is None


# ── Test 8: backward-compat with old payload shape (no new flag) ───────────


def test_old_payload_shape_still_works(gateway_env):
    # Old callers that omit allowReplaceShorterGrant still get sensible
    # behavior — same as the default (reuse when possible).
    gateway_env["insert_active_ssh_grant"](
        grant_id="g_legacy",
        level=1,
        host="server",
        principal="kyle",
        remaining_minutes=20,
        requestor="Lisa",
    )
    resp = gateway_env["client"].post(
        "/api/grants/request",
        headers=HEADERS,
        json={
            "resourceType": "ssh",
            "level": 1,
            "host": "server",
            "principal": "kyle",
            "description": "deploy",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["action"] == "reused_active_grant"
    assert body["grantId"] == "g_legacy"
