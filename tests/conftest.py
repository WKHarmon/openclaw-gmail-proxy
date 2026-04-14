"""Pytest fixtures for SSH grant dedupe / reuse tests.

These tests exercise the gateway's grant-request route + the
``find_active_ssh_grant`` helper without bringing up any external systems
(Signal, Vault, Gmail API). We:

  * redirect ``GRANTS_DB_PATH`` at a temp file for each test
  * monkey-patch ``send_signal_message`` to a no-op
  * inject a minimal SSH provider into the provider registry so the grant
    route can accept ``resourceType=ssh`` requests
  * build a tiny FastAPI app that only mounts the grants route
"""

from __future__ import annotations

import importlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# Ensure the repo root is on sys.path so ``import gateway`` works when
# pytest is invoked from anywhere.
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


# ── Minimal in-memory SSH provider for tests ────────────────────────────────


class FakeSSHProvider:
    """Stand-in for the real SSHProvider.

    Accepts any level-1/2/3 request shape with a ``principal`` and (for L1)
    a ``host`` or (for L2) a ``hostGroup``. Does not hit Vault.
    """

    resource_type = "ssh"
    display_name = "SSH"

    def validate_request(self, level, params):
        if level not in (1, 2, 3):
            return "level must be 1, 2, or 3"
        if not params.get("principal"):
            return "principal required"
        if level == 1 and not params.get("host"):
            return "host required for L1"
        if level == 2 and not params.get("hostGroup"):
            return "hostGroup required for L2"
        return None

    def default_duration(self, level):
        return {1: 30, 2: 30, 3: 15}[level]

    def format_signal_notification(self, grant, approval_url):
        return f"test-ssh-grant {grant['id']} -> {approval_url}"

    def format_approval_details(self, grant):
        return "<p>test</p>"

    async def on_approved(self, grant):
        pass

    async def on_revoked(self, grant):
        pass


# ── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture
def gateway_env(tmp_path, monkeypatch):
    """Set up an isolated gateway environment for a single test.

    Yields a dict with:
      * ``app``:    a FastAPI app with just the grants route registered
      * ``client``: a TestClient bound to that app
      * ``insert_active_ssh_grant``: helper that inserts a fully-active SSH grant
      * ``config``: the live CONFIG dict (so tests can tweak e.g. rate limits)
    """
    # Import gateway modules — safe because ``gateway.config`` just reads
    # the committed config.json, which we then mutate in-place.
    from gateway import config as config_mod
    from gateway import db as db_mod
    from gateway import grants as grants_mod
    from gateway.audit import audit as _audit  # noqa: F401
    from gateway.providers import _providers, register_provider
    from gateway.routes import grants as grants_routes
    from gateway import signal as signal_mod

    # Redirect DB + audit log to tmp_path
    db_path = tmp_path / "grants.db"
    audit_path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(config_mod, "GRANTS_DB_PATH", db_path)
    monkeypatch.setattr(config_mod, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config_mod, "AUDIT_LOG_PATH", audit_path)
    monkeypatch.setattr(db_mod, "GRANTS_DB_PATH", db_path)
    monkeypatch.setattr(db_mod, "DATA_DIR", tmp_path)
    # audit module imports AUDIT_LOG_PATH at import-time — patch its binding too
    import gateway.audit as audit_mod
    monkeypatch.setattr(audit_mod, "AUDIT_LOG_PATH", audit_path)

    # Reset the rate-limit deque between tests
    grants_routes._grant_request_times.clear()

    # Ensure CONFIG has the SSH provider enabled + a valid approval_url_base
    config_mod.CONFIG.setdefault("approval_url_base", "https://test.local")
    config_mod.CONFIG.setdefault(
        "providers", {}
    ).setdefault("ssh", {"enabled": True, "defaults": {"level1_ttl_minutes": 30}})

    # Monkey-patch Signal send so tests don't hit the network
    async def _noop_send(message):
        return

    monkeypatch.setattr(signal_mod, "send_signal_message", _noop_send)
    monkeypatch.setattr(grants_routes, "send_signal_message", _noop_send)

    # Register the fake SSH provider (save + restore)
    prior = dict(_providers)
    _providers.clear()
    register_provider(FakeSSHProvider())

    # Initialise the fresh DB
    db_mod.init_db()

    # Build a minimal FastAPI app with the grants route + SSH provider route
    app = FastAPI()

    async def _fire_callback(grant, status, expires_at=None):
        return

    grants_routes.register(app, fire_callback=_fire_callback)

    # Mount the real SSH provider's routes (for /api/ssh/credentials) and
    # monkey-patch vault.sign_ssh_key to return a deterministic fake cert.
    from gateway.providers import ssh as ssh_module

    async def _fake_sign_ssh_key(*, mount, role, public_key, valid_principals, ttl):
        return {
            "signed_key": f"FAKE-CERT-{valid_principals}-ttl{ttl}",
            "serial_number": "FAKESERIAL",
        }

    monkeypatch.setattr(ssh_module.vault, "sign_ssh_key", _fake_sign_ssh_key)
    ssh_module._register_ssh_routes(app)
    client = TestClient(app)

    def insert_active_ssh_grant(
        *,
        grant_id: str,
        level: int,
        host: str | None = None,
        host_group: str | None = None,
        principal: str,
        role: str | None = None,
        remaining_minutes: int = 20,
        requestor: str = "TestAgent",
    ):
        params: dict = {"principal": principal}
        if host:
            params["host"] = host
        if host_group:
            params["hostGroup"] = host_group
        if role:
            params["role"] = role
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=remaining_minutes)
        conn = db_mod.db_conn()
        try:
            conn.execute(
                "INSERT INTO grants (id, level, status, description, approval_token, "
                "signal_code, created_at, approved_at, expires_at, duration_minutes, "
                "metadata, resource_type, resource_params, requestor) "
                "VALUES (?, ?, 'active', 'test', ?, ?, ?, ?, ?, ?, '{}', 'ssh', ?, ?)",
                (
                    grant_id,
                    level,
                    f"tok_{grant_id}",
                    "AB12CD",
                    now.isoformat(),
                    now.isoformat(),
                    expires_at.isoformat(),
                    remaining_minutes,
                    json.dumps(params),
                    requestor,
                ),
            )
            conn.commit()
        finally:
            conn.close()
        return {"id": grant_id, "expires_at": expires_at.isoformat()}

    try:
        yield {
            "app": app,
            "client": client,
            "insert_active_ssh_grant": insert_active_ssh_grant,
            "config": config_mod.CONFIG,
            "db_conn": db_mod.db_conn,
        }
    finally:
        # Restore provider registry
        _providers.clear()
        _providers.update(prior)


# Requestor headers: bypass the api-key middleware (which isn't mounted on
# the minimal test app anyway) while still letting the route pick up the
# requestor name via ``request.state`` defaulting to CONFIG.agent_name.
HEADERS = {"Content-Type": "application/json"}
