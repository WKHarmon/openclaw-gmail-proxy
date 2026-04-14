"""Tests for the one-call, scope-based POST /api/ssh/credentials path.

When called with ``{level, host/hostGroup, principal, description, publicKey}``
(i.e. no ``grantId``), the endpoint resolves a matching active grant and
mints a cert in a single round-trip — or creates a new pending approval if
no active grant matches.
"""

from __future__ import annotations

from conftest import HEADERS  # noqa: E402


# ── Scope mode + active matching grant → cert minted ────────────────────────


def test_scope_mode_reuses_active_grant_and_mints_cert(gateway_env):
    gateway_env["insert_active_ssh_grant"](
        grant_id="g_reuse_mint",
        level=1,
        host="server",
        principal="kyle",
        remaining_minutes=20,
        requestor="Lisa",
    )
    resp = gateway_env["client"].post(
        "/api/ssh/credentials",
        headers=HEADERS,
        json={
            "publicKey": "ssh-ed25519 AAAAfake",
            "level": 1,
            "host": "server",
            "principal": "kyle",
            "description": "deploy",
            "durationMinutes": 10,
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["certificateIssued"] is True
    assert body["grantId"] == "g_reuse_mint"
    assert body["reused"] is True
    assert body["action"] == "reused_active_grant"
    assert body["durationSatisfied"] is True
    assert body["signedKey"].startswith("FAKE-CERT-kyle")
    assert body["serial"] == "FAKESERIAL"

    # Confirm still only one grant — no new one was created.
    conn = gateway_env["db_conn"]()
    try:
        count = conn.execute("SELECT COUNT(*) FROM grants").fetchone()[0]
    finally:
        conn.close()
    assert count == 1


# ── Scope mode + no matching grant → new pending request, no cert ──────────


def test_scope_mode_no_match_creates_pending_no_cert(gateway_env):
    resp = gateway_env["client"].post(
        "/api/ssh/credentials",
        headers=HEADERS,
        json={
            "publicKey": "ssh-ed25519 AAAAfake",
            "level": 1,
            "host": "server",
            "principal": "kyle",
            "description": "first deploy",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["certificateIssued"] is False
    assert body["action"] == "requested_new_grant"
    assert body["status"] == "pending"
    assert body["reused"] is False
    assert body["grantId"].startswith("g_")
    assert "signedKey" not in body


# ── Scope mode + shorter existing grant → cert minted, shortfall reported ─


def test_scope_mode_shorter_grant_is_reused_with_shortfall_flags(gateway_env):
    gateway_env["insert_active_ssh_grant"](
        grant_id="g_short_reuse",
        level=1,
        host="server",
        principal="kyle",
        remaining_minutes=2,
        requestor="Lisa",
    )
    resp = gateway_env["client"].post(
        "/api/ssh/credentials",
        headers=HEADERS,
        json={
            "publicKey": "ssh-ed25519 AAAAfake",
            "level": 1,
            "host": "server",
            "principal": "kyle",
            "description": "deploy",
            "durationMinutes": 60,
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["certificateIssued"] is True
    assert body["grantId"] == "g_short_reuse"
    assert body["durationSatisfied"] is False
    assert body["shorterThanRequested"] is True
    assert body["requestedDurationSeconds"] == 60 * 60
    assert body["signedKey"].startswith("FAKE-CERT-kyle")


# ── Scope mode + explicit replacement → pending, no cert, previousGrantId ─


def test_scope_mode_explicit_replacement_returns_pending(gateway_env):
    gateway_env["insert_active_ssh_grant"](
        grant_id="g_short_replace",
        level=1,
        host="server",
        principal="kyle",
        remaining_minutes=1,
        requestor="Lisa",
    )
    resp = gateway_env["client"].post(
        "/api/ssh/credentials",
        headers=HEADERS,
        json={
            "publicKey": "ssh-ed25519 AAAAfake",
            "level": 1,
            "host": "server",
            "principal": "kyle",
            "description": "longer deploy",
            "durationMinutes": 120,
            "allowReplaceShorterGrant": True,
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["certificateIssued"] is False
    assert body["action"] == "requested_replacement_grant_due_to_short_duration"
    assert body["previousGrantId"] == "g_short_replace"
    assert body["status"] == "pending"
    assert "signedKey" not in body


# ── Classic grantId mode still works alongside the new scope mode ─────────


def test_classic_grant_id_mode_still_works(gateway_env):
    g = gateway_env["insert_active_ssh_grant"](
        grant_id="g_classic",
        level=1,
        host="server",
        principal="kyle",
        remaining_minutes=15,
        requestor="Lisa",
    )
    resp = gateway_env["client"].post(
        "/api/ssh/credentials",
        headers=HEADERS,
        json={
            "grantId": g["id"],
            "publicKey": "ssh-ed25519 AAAAfake",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["certificateIssued"] is True
    assert body["grantId"] == "g_classic"
    assert body["signedKey"].startswith("FAKE-CERT-kyle")
    # Classic path does not include reuse metadata (caller already picked the grant)
    assert "action" not in body
    assert "reused" not in body


# ── Scope mode missing required fields → 400 ──────────────────────────────


def test_scope_mode_missing_fields_returns_400(gateway_env):
    resp = gateway_env["client"].post(
        "/api/ssh/credentials",
        headers=HEADERS,
        json={
            "publicKey": "ssh-ed25519 AAAAfake",
            # missing level, principal, description
        },
    )
    assert resp.status_code == 400
    assert "scope" in resp.text.lower() or "level" in resp.text.lower()


# ── Bogus grantId → 403 (unchanged behavior) ──────────────────────────────


def test_bogus_grant_id_returns_403(gateway_env):
    resp = gateway_env["client"].post(
        "/api/ssh/credentials",
        headers=HEADERS,
        json={
            "grantId": "g_does_not_exist",
            "publicKey": "ssh-ed25519 AAAAfake",
        },
    )
    assert resp.status_code == 403


# ── Reuses don't consume the rate-limit bucket ────────────────────────────


def test_reuse_does_not_consume_rate_limit(gateway_env):
    """Flood the endpoint with reuses — they should NOT hit the rate limit,
    because no new grant is being created. Only real creates count."""
    # Set rate limit low to make the test cheap.
    gateway_env["config"]["rate_limit"]["grant_requests_per_minute"] = 2
    gateway_env["insert_active_ssh_grant"](
        grant_id="g_many_reuses",
        level=1,
        host="server",
        principal="kyle",
        remaining_minutes=30,
        requestor="Lisa",
    )
    # 10 rapid reuses — all should succeed with cert minted.
    for _ in range(10):
        resp = gateway_env["client"].post(
            "/api/ssh/credentials",
            headers=HEADERS,
            json={
                "publicKey": "ssh-ed25519 AAAAfake",
                "level": 1,
                "host": "server",
                "principal": "kyle",
                "description": "deploy",
            },
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["certificateIssued"] is True
        assert body["grantId"] == "g_many_reuses"
