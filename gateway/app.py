"""FastAPI app creation, lifespan, and provider wiring."""

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI

from gateway.audit import audit
from gateway.callbacks import fire_grant_callback
from gateway.config import CONFIG, DATA_DIR, VAULT_ENABLED, get_requestors
from gateway.db import db_conn, init_db
from gateway.middleware import check_api_key
from gateway.providers import all_providers, register_provider
from gateway.providers.gmail import GmailProvider
from gateway.vault import vault

log = logging.getLogger("gateway")

# ── Module-level state loaded at startup ──────────────────────────────────

# Mapping: API key -> requestor name
_api_keys: dict[str, str] = {}

# Mapping: requestor name -> callback credentials dict
# Each dict has keys: url, cf_auth, cf_client_id, cf_client_secret, hooks_token
_requestor_callbacks: dict[str, dict] = {}


def get_api_keys() -> dict[str, str]:
    return _api_keys


def get_requestor_callback(requestor_name: str) -> dict:
    return _requestor_callbacks.get(requestor_name, {})


def make_fire_callback():
    """Return an async callable for firing grant callbacks with loaded credentials."""
    async def _fire(grant, status, expires_at=None):
        requestor = grant.get("requestor", "")
        await fire_grant_callback(
            grant, status, expires_at,
            requestor_name=requestor,
        )
    return _fire


# ── Background tasks ──────────────────────────────────────────────────────

async def _expire_grants_loop():
    """Periodically expire stale grants."""
    while True:
        try:
            now = datetime.now(timezone.utc).isoformat()
            approval_cutoff = (
                datetime.now(timezone.utc) - timedelta(minutes=10)
            ).isoformat()

            conn = db_conn()
            try:
                expired = conn.execute(
                    "SELECT id FROM grants WHERE status='active' "
                    "AND expires_at IS NOT NULL AND expires_at<=?",
                    (now,),
                ).fetchall()
                for row in expired:
                    conn.execute(
                        "UPDATE grants SET status='expired' WHERE id=?", (row["id"],)
                    )
                    audit({"action": "grant_expired", "grantId": row["id"]})

                stale = conn.execute(
                    "SELECT id FROM grants WHERE status='pending' AND created_at<?",
                    (approval_cutoff,),
                ).fetchall()
                for row in stale:
                    conn.execute(
                        "UPDATE grants SET status='expired' WHERE id=?", (row["id"],)
                    )
                    audit({
                        "action": "grant_expired",
                        "grantId": row["id"],
                        "reason": "approval_timeout",
                    })

                conn.commit()
            finally:
                conn.close()
        except Exception as e:
            log.error("Grant expiry loop error: %s", e)
        await asyncio.sleep(15)


# ── Lifespan ──────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Load API keys and callback credentials for all requestors. Clear any
    # previous in-process state first so reload/test lifespans cannot carry
    # stale credentials forward.
    _api_keys.clear()
    _requestor_callbacks.clear()
    requestors = get_requestors()
    api_key_load_errors: list[str] = []

    if VAULT_ENABLED:
        # Load shared CF Access credentials (used for callbacks behind Cloudflare)
        shared_cf_id = ""
        shared_cf_secret = ""
        try:
            shared_secrets = vault.read_all()
            shared_cf_id = shared_secrets.get("CF-Access-Client-Id", "")
            shared_cf_secret = shared_secrets.get("CF-Access-Client-Secret", "")
            if shared_cf_id:
                log.info("Shared CF Access credentials loaded from Vault")
        except Exception as e:
            log.warning("Could not load shared CF credentials: %s", e)

        for name, rcfg in requestors.items():
            # Load API key
            api_key_path = rcfg.get("api_key_vault_path", "")
            if api_key_path:
                try:
                    secret = vault.read_path(api_key_path)
                    key = secret["api_key"].strip()
                    _api_keys[key] = name
                    log.info("API key loaded for requestor %r", name)
                except Exception as e:
                    log.error("Could not load API key for requestor %r: %s", name, e)
                    api_key_load_errors.append(f"{name}: {e}")
            else:
                msg = f"No api_key_vault_path for requestor {name!r}"
                log.error(msg)
                api_key_load_errors.append(msg)

            # Load callback credentials
            cb_cfg = rcfg.get("callback")
            if cb_cfg:
                cb_creds = {
                    "url": cb_cfg.get("url", ""),
                    "cf_auth": cb_cfg.get("cf_auth", False),
                    "cf_client_id": shared_cf_id,
                    "cf_client_secret": shared_cf_secret,
                    "hooks_token": "",
                }
                hooks_vault_path = cb_cfg.get("hooks_token_vault_path", "")
                if hooks_vault_path:
                    try:
                        gw = vault.read_path(hooks_vault_path)
                        cb_creds["hooks_token"] = gw.get("hooks_token", "")
                        if cb_creds["hooks_token"]:
                            log.info("Callback hooks token loaded for requestor %r", name)
                    except Exception as e:
                        log.warning("Could not load hooks token for requestor %r: %s", name, e)
                _requestor_callbacks[name] = cb_creds
    else:
        # Non-Vault mode: single API key from environment (legacy)
        env_key = os.environ.get("API_KEY", "").strip()
        if env_key:
            fallback_name = CONFIG.get("agent_name", "Agent")
            _api_keys[env_key] = fallback_name
            log.info("API key loaded from environment for %r", fallback_name)
        else:
            log.warning("API_KEY not set — /api/* routes are unauthenticated")

        hooks_token = os.environ.get("CALLBACK_HOOKS_TOKEN", "")
        if hooks_token:
            cb_cfg = CONFIG.get("callback", {})
            name = CONFIG.get("agent_name", "Agent")
            _requestor_callbacks[name] = {
                "url": cb_cfg.get("url", ""),
                "cf_auth": cb_cfg.get("cf_auth", False),
                "cf_client_id": "",
                "cf_client_secret": "",
                "hooks_token": hooks_token,
            }
            log.info("Callback hooks token loaded from environment")

    if api_key_load_errors:
        raise RuntimeError(
            "Required API key secrets could not be loaded: "
            + "; ".join(api_key_load_errors)
        )

    if not _api_keys:
        raise RuntimeError("No API keys loaded; refusing to start with /api/* unauthenticated")

    if not CONFIG.get("signal", {}).get("webhook_token"):
        log.warning("signal.webhook_token not set — webhook endpoint is unauthenticated")

    # Init database
    init_db()
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # Start providers (already registered during create_app)
    for p in all_providers().values():
        await p.startup()

    # Start background tasks
    tasks = [asyncio.create_task(_expire_grants_loop())]
    log.info("Authorization gateway started on port %s", CONFIG.get("port", 18795))

    yield

    for t in tasks:
        t.cancel()


# ── App factory ───────────────────────────────────────────────────────────

def create_app() -> FastAPI:
    application = FastAPI(title="Agent Authorization Gateway", lifespan=lifespan)
    application.middleware("http")(check_api_key)

    # Register shared routes
    from gateway.routes import health, audit as audit_routes, grants, approval
    from gateway.signal import signal_webhook

    _fire_callback = make_fire_callback()

    health.register(application)
    audit_routes.register(application)
    grants.register(application, fire_callback=_fire_callback)
    approval.register(application, fire_callback=_fire_callback)

    # Signal webhook
    application.post("/internal/signal-webhook")(signal_webhook)

    # Register providers and their routes (routes registered at creation time,
    # startup() called during lifespan)
    gmail = GmailProvider()
    register_provider(gmail)
    gmail.register_routes(application)

    ssh_cfg = CONFIG.get("providers", {}).get("ssh", {})
    if ssh_cfg.get("enabled"):
        from gateway.providers.ssh import SSHProvider
        ssh = SSHProvider()
        register_provider(ssh)
        ssh.register_routes(application)

    return application


app = create_app()
