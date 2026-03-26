#!/usr/bin/env python3
"""Gmail Access Proxy — Tiered, time-limited email access with human approval."""

import asyncio
import base64
import hmac
import json
import logging
import os
import secrets
import sqlite3
import time
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from email.utils import parseaddr
from fnmatch import fnmatch
from html import escape
from pathlib import Path
from typing import Optional
import httpx
import uvicorn
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleAuthRequest
from googleapiclient.discovery import build

# ─── Logging ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
log = logging.getLogger("email-proxy")

# ─── Configuration ────────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).parent
CONFIG_PATH = BASE_DIR / "config.json"
DATA_DIR = BASE_DIR / "data"
AUDIT_LOG_PATH = DATA_DIR / "audit.jsonl"
GRANTS_DB_PATH = DATA_DIR / "grants.db"

VAULT_ADDR = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
VAULT_ROLE_ID = os.environ.get("VAULT_ROLE_ID", "")
VAULT_SECRET_ID = os.environ.get("VAULT_SECRET_ID", "")
VAULT_ENABLED = bool(VAULT_ROLE_ID and VAULT_SECRET_ID)
_api_key: str = ""
_callback_cf_client_id: str = ""
_callback_cf_client_secret: str = ""
_callback_hooks_token: str = ""

# CSRF tokens for approval forms: approval_token -> (csrf_token, expiry_monotonic)
_csrf_tokens: dict[str, tuple[str, float]] = {}

# Rate limiting for grant requests
_grant_request_times: deque = deque()


def load_config() -> dict:
    with open(CONFIG_PATH) as f:
        return json.load(f)


def load_sensitive_patterns(config: dict) -> dict:
    path = BASE_DIR / config.get("sensitive_patterns_file", "sensitive_patterns.json")
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return {"redact_subjects": [], "redact_senders": []}


CONFIG = load_config()
SENSITIVE = load_sensitive_patterns(CONFIG)

# ─── Secrets Backend ─────────────────────────────────────────────────────────
#
# If VAULT_ROLE_ID and VAULT_SECRET_ID are set, secrets are read from Vault.
# Otherwise, secrets are read from environment variables:
#   API_KEY, GMAIL_CLIENT_ID, GMAIL_CLIENT_SECRET, GMAIL_REFRESH_TOKEN,
#   GMAIL_ACCESS_TOKEN, CF_ACCESS_CLIENT_ID, CF_ACCESS_CLIENT_SECRET

if VAULT_ENABLED:
    _vault_client = httpx.Client(timeout=10.0)
    _vault_token: str = ""
    _vault_token_expires: float = 0.0  # monotonic time

    def _vault_login():
        """Authenticate to Vault via AppRole and cache the client token."""
        global _vault_token, _vault_token_expires

        resp = _vault_client.post(
            f"{VAULT_ADDR}/v1/auth/approle/login",
            json={"role_id": VAULT_ROLE_ID, "secret_id": VAULT_SECRET_ID},
        )
        resp.raise_for_status()
        auth = resp.json()["auth"]
        _vault_token = auth["client_token"]
        lease = auth.get("lease_duration", 3600)
        _vault_token_expires = time.monotonic() + lease * 0.75
        log.info("Vault AppRole login successful (lease %ds)", lease)

    def _vault_api_path() -> str:
        """Convert vault_path 'secret/gmail-proxy' → KV v2 API path 'secret/data/gmail-proxy'."""
        parts = CONFIG["vault_path"].split("/", 1)
        mount = parts[0]
        key = parts[1] if len(parts) > 1 else ""
        return f"{mount}/data/{key}"

    def _vault_headers() -> dict:
        if not _vault_token or time.monotonic() >= _vault_token_expires:
            _vault_login()
        return {"X-Vault-Token": _vault_token}

    def vault_read_all() -> dict:
        """Read all fields from the vault secret."""
        resp = _vault_client.get(
            f"{VAULT_ADDR}/v1/{_vault_api_path()}",
            headers=_vault_headers(),
        )
        resp.raise_for_status()
        return resp.json()["data"]["data"]

    def vault_read_path(kv_path: str) -> dict:
        """Read from an arbitrary KV v2 path."""
        parts = kv_path.split("/", 1)
        mount = parts[0]
        key = parts[1] if len(parts) > 1 else ""
        api_path = f"{mount}/data/{key}"
        resp = _vault_client.get(
            f"{VAULT_ADDR}/v1/{api_path}",
            headers=_vault_headers(),
        )
        resp.raise_for_status()
        return resp.json()["data"]["data"]

    def vault_patch(data: dict):
        """Update specific fields in the vault secret (KV v2 patch)."""
        resp = _vault_client.patch(
            f"{VAULT_ADDR}/v1/{_vault_api_path()}",
            headers={**_vault_headers(), "Content-Type": "application/merge-patch+json"},
            json={"data": data},
        )
        if resp.status_code >= 400:
            current = vault_read_all()
            current.update(data)
            resp = _vault_client.post(
                f"{VAULT_ADDR}/v1/{_vault_api_path()}",
                headers=_vault_headers(),
                json={"data": current},
            )
            resp.raise_for_status()

else:
    log.info("Vault not configured — reading secrets from environment variables")

    def vault_read_all() -> dict:
        """Read Gmail secrets from environment variables."""
        return {
            "client_id": os.environ.get("GMAIL_CLIENT_ID", ""),
            "client_secret": os.environ.get("GMAIL_CLIENT_SECRET", ""),
            "refresh_token": os.environ.get("GMAIL_REFRESH_TOKEN", ""),
            "access_token": os.environ.get("GMAIL_ACCESS_TOKEN", ""),
            "CF-Access-Client-Id": os.environ.get("CF_ACCESS_CLIENT_ID", ""),
            "CF-Access-Client-Secret": os.environ.get("CF_ACCESS_CLIENT_SECRET", ""),
        }

    def vault_read_path(kv_path: str) -> dict:
        """Read API key from environment variable."""
        return {"api_key": os.environ.get("API_KEY", "")}

    def vault_patch(data: dict):
        """No-op when Vault is disabled (refreshed tokens are not persisted)."""
        pass

# ─── Gmail Client ────────────────────────────────────────────────────────────

_gmail_service = None
_credentials: Optional[Credentials] = None


def get_gmail_service():
    """Get or refresh the authenticated Gmail API service."""
    global _gmail_service, _credentials

    if _credentials is not None and _credentials.valid:
        return _gmail_service

    # Refresh existing credentials
    if _credentials is not None and _credentials.expired and _credentials.refresh_token:
        _credentials.refresh(GoogleAuthRequest())
        try:
            vault_patch({"access_token": _credentials.token})
        except Exception as e:
            log.warning(f"Failed to persist refreshed access token to vault: {e}")
        _gmail_service = build("gmail", "v1", credentials=_credentials, cache_discovery=False)
        return _gmail_service

    # Fresh load from vault
    vault_secrets = vault_read_all()
    _credentials = Credentials(
        token=vault_secrets.get("access_token"),
        refresh_token=vault_secrets["refresh_token"],
        token_uri="https://oauth2.googleapis.com/token",
        client_id=vault_secrets["client_id"],
        client_secret=vault_secrets["client_secret"],
        scopes=["https://www.googleapis.com/auth/gmail.readonly"],
    )

    if not _credentials.valid:
        _credentials.refresh(GoogleAuthRequest())
        try:
            vault_patch({"access_token": _credentials.token})
        except Exception as e:
            log.warning(f"Failed to persist access token to vault: {e}")

    _gmail_service = build("gmail", "v1", credentials=_credentials, cache_discovery=False)
    return _gmail_service

# ─── SQLite Grant Store ──────────────────────────────────────────────────────


def init_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(GRANTS_DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS grants (
            id TEXT PRIMARY KEY,
            level INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            message_id TEXT,
            query TEXT,
            description TEXT,
            approval_token TEXT UNIQUE NOT NULL,
            signal_code TEXT,
            created_at TEXT NOT NULL,
            approved_at TEXT,
            expires_at TEXT,
            duration_minutes INTEGER,
            metadata TEXT,
            callback_url TEXT
        )
    """)
    # Migrate: add callback_url if missing (existing DBs)
    try:
        conn.execute("ALTER TABLE grants ADD COLUMN callback_url TEXT")
    except sqlite3.OperationalError:
        pass  # Column already exists
    conn.commit()
    conn.close()


def db_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(GRANTS_DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

# ─── Audit Log ────────────────────────────────────────────────────────────────


def audit(entry: dict):
    entry["ts"] = datetime.now(timezone.utc).isoformat()
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(AUDIT_LOG_PATH, "a") as f:
        f.write(json.dumps(entry, default=str) + "\n")
    log.info("AUDIT %s", entry.get("action", "unknown"))

# ─── Sensitive Pattern Matching ───────────────────────────────────────────────


def is_sensitive(subject: str, sender: str) -> Optional[str]:
    """Return the matched pattern name if the email is sensitive, else None."""
    subject_lower = subject.lower()
    for pattern in SENSITIVE.get("redact_subjects", []):
        if pattern.lower() in subject_lower:
            return pattern

    sender_email = parseaddr(sender)[1].lower()
    for pattern in SENSITIVE.get("redact_senders", []):
        if fnmatch(sender_email, pattern.lower()):
            return f"sender:{pattern}"

    return None

# ─── Signal ──────────────────────────────────────────────────────────────────


async def send_signal_message(message: str):
    signal_cfg = CONFIG["signal"]
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            resp = await client.post(
                f"{signal_cfg['api_url']}/v2/send",
                json={
                    "number": signal_cfg["sender"],
                    "recipients": [signal_cfg["approver"]],
                    "message": message,
                },
            )
            if resp.status_code not in (200, 201):
                log.error("Signal send failed: %s %s", resp.status_code, resp.text)
        except Exception as e:
            log.error("Signal send error (%s): %s", type(e).__name__, e)

# ─── Grant Callback ──────────────────────────────────────────────────────────


async def fire_grant_callback(grant: dict, status: str, expires_at: Optional[str] = None):
    """POST grant status to the configured callback URL."""
    callback_cfg = CONFIG.get("callback", {})
    callback_url = callback_cfg.get("url", "")
    if not callback_url:
        return

    # Check if this grant opted out of callbacks
    meta = json.loads(grant.get("metadata") or "{}")
    if meta.get("callback") is False:
        return

    payload = {
        "grantId": grant["id"],
        "level": grant["level"],
        "status": status,
    }
    if expires_at:
        payload["expiresAt"] = expires_at
    if meta.get("callbackSessionKey"):
        payload["sessionKey"] = meta["callbackSessionKey"]

    headers: dict = {"Content-Type": "application/json"}
    if callback_cfg.get("cf_auth") and _callback_cf_client_id:
        headers["CF-Access-Client-Id"] = _callback_cf_client_id
        headers["CF-Access-Client-Secret"] = _callback_cf_client_secret
    if _callback_hooks_token:
        headers["Authorization"] = f"Bearer {_callback_hooks_token}"

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.post(callback_url, json=payload, headers=headers)
            if resp.status_code >= 400:
                log.error("Grant callback failed: %s %s", resp.status_code, resp.text)
            else:
                log.info("Grant callback sent to %s (status=%s)", callback_url, status)
        except Exception as e:
            log.error("Grant callback error: %s", e)

# ─── Grant Helpers ────────────────────────────────────────────────────────────


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
        "level": grant["level"],
        "expiresAt": expires_at.isoformat(),
        "approvedVia": via,
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
        "level": grant["level"],
        "deniedVia": via,
    })

# ─── Email Helpers ────────────────────────────────────────────────────────────


def extract_metadata(msg: dict) -> dict:
    headers = {}
    for h in msg.get("payload", {}).get("headers", []):
        headers[h["name"].lower()] = h["value"]
    return {
        "id": msg["id"],
        "threadId": msg.get("threadId"),
        "labelIds": msg.get("labelIds", []),
        "from": headers.get("from", ""),
        "to": headers.get("to", ""),
        "subject": headers.get("subject", ""),
        "date": headers.get("date", ""),
        "internalDate": msg.get("internalDate"),
    }


def extract_body(payload: dict) -> str:
    """Recursively extract email body text, preferring text/plain."""
    body_text = ""

    if payload.get("body", {}).get("data"):
        body_text = base64.urlsafe_b64decode(payload["body"]["data"]).decode(
            "utf-8", errors="replace"
        )

    for part in payload.get("parts", []):
        mime = part.get("mimeType", "")
        if mime == "text/plain" and part.get("body", {}).get("data"):
            return base64.urlsafe_b64decode(part["body"]["data"]).decode(
                "utf-8", errors="replace"
            )
        elif mime == "text/html" and part.get("body", {}).get("data") and not body_text:
            body_text = base64.urlsafe_b64decode(part["body"]["data"]).decode(
                "utf-8", errors="replace"
            )
        elif mime.startswith("multipart/"):
            nested = extract_body(part)
            if nested:
                body_text = nested

    return body_text


def extract_attachment_metadata(payload: dict) -> list[dict]:
    """Recursively walk MIME parts, returning metadata for attachments."""
    attachments = []

    def _walk(part):
        body = part.get("body", {})
        filename = part.get("filename", "")
        if body.get("attachmentId") or (filename and body.get("size", 0) > 0):
            attachments.append({
                "attachmentId": body.get("attachmentId", ""),
                "filename": filename,
                "mimeType": part.get("mimeType", "application/octet-stream"),
                "size": body.get("size", 0),
                "partId": part.get("partId", ""),
            })
        for sub in part.get("parts", []):
            _walk(sub)

    _walk(payload)
    return attachments

# ─── Grant Checking ──────────────────────────────────────────────────────────


def get_active_grant_for_message(
    message_id: str, include_consumed: bool = False,
) -> Optional[dict]:
    """Find an active, unexpired grant that covers this message.

    If include_consumed is True, also match consumed Level 1 grants that
    haven't expired yet (for attachment downloads after body read).
    """
    now = datetime.now(timezone.utc).isoformat()
    conn = db_conn()
    try:
        # Level 1 — specific message
        if include_consumed:
            row = conn.execute(
                "SELECT * FROM grants WHERE status IN ('active','consumed') AND level=1 "
                "AND message_id=? AND expires_at>?",
                (message_id, now),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT * FROM grants WHERE status='active' AND level=1 "
                "AND message_id=? AND expires_at>?",
                (message_id, now),
            ).fetchone()
        if row:
            return dict(row)

        # Level 2 — query-based (verify message matches)
        rows = conn.execute(
            "SELECT * FROM grants WHERE status='active' AND level=2 AND expires_at>?",
            (now,),
        ).fetchall()
        for row in rows:
            grant = dict(row)
            if _message_matches_query(message_id, grant["query"]):
                return grant

        # Level 3 — full access
        row = conn.execute(
            "SELECT * FROM grants WHERE status='active' AND level=3 AND expires_at>?",
            (now,),
        ).fetchone()
        if row:
            return dict(row)

        return None
    finally:
        conn.close()


def _message_matches_query(message_id: str, query: str) -> bool:
    """Check whether message_id appears in the results of a Gmail query."""
    try:
        service = get_gmail_service()
        results = service.users().messages().list(
            userId="me", q=query, maxResults=500
        ).execute()
        return message_id in {m["id"] for m in results.get("messages", [])}
    except Exception as e:
        log.error("Query match check failed: %s", e)
        return False

# ─── App Lifecycle ────────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _api_key, _callback_cf_client_id, _callback_cf_client_secret, _callback_hooks_token
    if VAULT_ENABLED:
        api_key_path = CONFIG.get("vault_api_key_path", "")
        if api_key_path:
            try:
                shared = vault_read_path(api_key_path)
                _api_key = shared["api_key"].strip()
                log.info("API key loaded from Vault")
            except Exception as e:
                log.warning("Could not load API key from Vault: %s — /api/* routes are unauthenticated", e)
        else:
            log.warning("vault_api_key_path not set in config — /api/* routes are unauthenticated")
    else:
        _api_key = os.environ.get("API_KEY", "").strip()
        if _api_key:
            log.info("API key loaded from environment")
        else:
            log.warning("API_KEY not set — /api/* routes are unauthenticated")
    try:
        gmail_secrets = vault_read_all()
        _callback_cf_client_id = gmail_secrets.get("CF-Access-Client-Id", "")
        _callback_cf_client_secret = gmail_secrets.get("CF-Access-Client-Secret", "")
        if _callback_cf_client_id:
            log.info("Callback CF Access credentials loaded from Vault")
    except Exception as e:
        log.warning("Could not load callback CF credentials: %s", e)
    # Load hooks token for grant callbacks
    callback_cfg = CONFIG.get("callback", {})
    hooks_vault_path = callback_cfg.get("hooks_token_vault_path", "")
    if hooks_vault_path and VAULT_ENABLED:
        try:
            gw = vault_read_path(hooks_vault_path)
            _callback_hooks_token = gw.get("hooks_token", "")
            if _callback_hooks_token:
                log.info("Callback hooks token loaded from Vault")
        except Exception as e:
            log.warning("Could not load hooks token from Vault: %s", e)
    elif not VAULT_ENABLED:
        _callback_hooks_token = os.environ.get("CALLBACK_HOOKS_TOKEN", "")
        if _callback_hooks_token:
            log.info("Callback hooks token loaded from environment")
    if not CONFIG.get("signal", {}).get("webhook_token"):
        log.warning("signal.webhook_token not set — webhook endpoint is unauthenticated")
    init_db()
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tasks = [asyncio.create_task(_expire_grants_loop())]
    log.info("Email proxy started on port %s", CONFIG.get("port", 18795))
    yield
    for t in tasks:
        t.cancel()


app = FastAPI(title="OpenClaw Gmail Proxy", lifespan=lifespan)

# ─── API Key Middleware ──────────────────────────────────────────────────────


@app.middleware("http")
async def check_api_key(request: Request, call_next):
    """Require Bearer token on /api/* routes. Health and approval pages are open."""
    if _api_key and request.url.path.startswith("/api/"):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or not hmac.compare_digest(auth[7:], _api_key):
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid or missing API key"},
            )
    return await call_next(request)

# ─── Background Tasks ────────────────────────────────────────────────────────


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
                # Expire active grants past their expiry
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

                # Expire pending grants that were never approved
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


async def _process_signal_reply(text: str):
    """Match a Signal reply to a pending grant and approve/deny."""
    text_upper = text.upper().strip()

    conn = db_conn()
    try:
        # Parse "YES-CODE", "Y-CODE", "NO-CODE", "N-CODE"
        has_code = "-" in text_upper
        if has_code:
            parts = text_upper.split("-", 1)
            keyword = parts[0]
            code = parts[1]
        else:
            keyword = text_upper
            code = None

        is_approve = keyword in ("YES", "Y", "APPROVE")
        is_deny = keyword in ("NO", "N", "DENY")

        if not is_approve and not is_deny:
            return

        if code:
            # Find pending grant with matching signal_code
            row = conn.execute(
                "SELECT * FROM grants WHERE status='pending' AND UPPER(signal_code)=?",
                (code,),
            ).fetchone()
            if not row:
                await send_signal_message(f"No pending request with code {code}.")
                return
            grant = dict(row)
        else:
            # No code — only works if exactly one pending grant
            rows = conn.execute(
                "SELECT * FROM grants WHERE status='pending'"
            ).fetchall()
            if len(rows) == 0:
                await send_signal_message("No pending access requests.")
                return
            elif len(rows) > 1:
                codes = ", ".join(dict(r)["signal_code"] for r in rows)
                await send_signal_message(
                    f"Multiple pending requests. Reply with code:\n{codes}"
                )
                return
            grant = dict(rows[0])

        if is_approve:
            expires_at = activate_grant(grant, via="signal")
            await fire_grant_callback(grant, "active", expires_at.isoformat())
            asyncio.create_task(send_signal_message(
                f"Approved (Level {grant['level']}). "
                f"Expires {expires_at.strftime('%H:%M UTC')}."
            ))
        else:
            deny_grant(grant, via="signal")
            await fire_grant_callback(grant, "denied")
            asyncio.create_task(send_signal_message("Denied."))

    finally:
        conn.close()

# ─── API: Health ──────────────────────────────────────────────────────────────


@app.get("/health")
async def health():
    return {"status": "ok"}

# ─── Signal Webhook ──────────────────────────────────────────────────────────


@app.post("/internal/signal-webhook")
async def signal_webhook(request: Request):
    """Receive incoming Signal messages from signal-api (json-rpc mode).

    Only accessible on the Docker network — not exposed via Cloudflare.
    Optionally authenticated via ?token= query parameter.
    """
    expected_token = CONFIG.get("signal", {}).get("webhook_token", "")
    if expected_token:
        provided_token = request.query_params.get("token", "")
        if not hmac.compare_digest(provided_token, expected_token):
            return JSONResponse(status_code=401, content={"detail": "Invalid webhook token"})

    approver_number = CONFIG["signal"]["approver"]

    try:
        payload = await request.json()
    except Exception:
        return {"status": "ignored"}

    # json-rpc mode wraps the envelope under "params"
    params = payload.get("params", payload)
    envelope = params.get("envelope", {})
    source = envelope.get("sourceNumber", "")
    data_msg = envelope.get("dataMessage", {})
    body = (data_msg.get("message") or "").strip()

    if source != approver_number or not body:
        return {"status": "ignored"}

    await _process_signal_reply(body)
    return {"status": "processed"}

# ─── API: Profile ────────────────────────────────────────────────────────────


@app.get("/api/profile")
async def get_profile():
    """Get the connected Gmail account profile."""
    service = await asyncio.to_thread(get_gmail_service)
    profile = await asyncio.to_thread(
        lambda: service.users().getProfile(userId="me").execute()
    )
    audit({"action": "profile_read"})
    return {
        "emailAddress": profile["emailAddress"],
        "messagesTotal": profile.get("messagesTotal", 0),
        "threadsTotal": profile.get("threadsTotal", 0),
        "historyId": profile.get("historyId", ""),
    }

# ─── API: Labels ─────────────────────────────────────────────────────────────


@app.get("/api/labels")
async def list_labels():
    """List all Gmail labels with message/thread counts."""
    service = await asyncio.to_thread(get_gmail_service)
    result = await asyncio.to_thread(
        lambda: service.users().labels().list(userId="me").execute()
    )

    # Batch-fetch full details (list only returns id/name/type)
    labels_raw = result.get("labels", [])
    batch = service.new_batch_http_request()
    labels: list[dict] = []

    def _cb(request_id, response, exception):
        if exception is None:
            labels.append({
                "id": response["id"],
                "name": response["name"],
                "type": response.get("type", "user"),
                "messagesTotal": response.get("messagesTotal", 0),
                "messagesUnread": response.get("messagesUnread", 0),
                "threadsTotal": response.get("threadsTotal", 0),
                "threadsUnread": response.get("threadsUnread", 0),
            })

    for lbl in labels_raw:
        batch.add(
            service.users().labels().get(userId="me", id=lbl["id"]),
            callback=_cb,
        )

    await asyncio.to_thread(batch.execute)
    audit({"action": "labels_list", "count": len(labels)})
    return {"labels": labels}


@app.get("/api/labels/{label_id}")
async def get_label(label_id: str):
    """Get details for a single label."""
    service = await asyncio.to_thread(get_gmail_service)
    try:
        lbl = await asyncio.to_thread(
            lambda: service.users().labels().get(userId="me", id=label_id).execute()
        )
    except Exception:
        raise HTTPException(404, "Label not found")
    audit({"action": "label_read", "labelId": label_id})
    return {
        "id": lbl["id"],
        "name": lbl["name"],
        "type": lbl.get("type", "user"),
        "messagesTotal": lbl.get("messagesTotal", 0),
        "messagesUnread": lbl.get("messagesUnread", 0),
        "threadsTotal": lbl.get("threadsTotal", 0),
        "threadsUnread": lbl.get("threadsUnread", 0),
    }

# ─── API: Level 0 — Email Metadata ───────────────────────────────────────────


@app.get("/api/emails")
async def list_emails(
    q: str = "",
    maxResults: int = Query(default=20, le=100),
    labelIds: Optional[str] = None,
    pageToken: Optional[str] = None,
):
    """List/search emails — Level 0, metadata only."""
    service = await asyncio.to_thread(get_gmail_service)

    kwargs: dict = {"userId": "me", "maxResults": maxResults}
    if q:
        kwargs["q"] = q
    if labelIds:
        kwargs["labelIds"] = labelIds.split(",")
    if pageToken:
        kwargs["pageToken"] = pageToken

    results = await asyncio.to_thread(
        lambda: service.users().messages().list(**kwargs).execute()
    )

    messages = []
    if "messages" in results:
        # Batch-fetch metadata
        batch = service.new_batch_http_request()
        fetched: list[dict] = []

        def _cb(request_id, response, exception):
            if exception is None:
                fetched.append(extract_metadata(response))
            else:
                log.warning("Batch fetch error for %s: %s", request_id, exception)

        for msg_ref in results["messages"]:
            batch.add(
                service.users().messages().get(
                    userId="me",
                    id=msg_ref["id"],
                    format="metadata",
                    metadataHeaders=["From", "To", "Subject", "Date"],
                ),
                callback=_cb,
            )

        await asyncio.to_thread(batch.execute)
        messages = fetched

    audit({
        "action": "metadata_search",
        "query": q or "(all)",
        "results": len(messages),
        "grant": "level0",
    })

    return {
        "messages": messages,
        "nextPageToken": results.get("nextPageToken"),
        "resultSizeEstimate": results.get("resultSizeEstimate", 0),
    }

# ─── API: Get Single Email ───────────────────────────────────────────────────


@app.get("/api/emails/{message_id}")
async def get_email(message_id: str, override_sensitive: bool = False):
    """Get email by ID. Metadata always; full body only with an active grant."""
    service = await asyncio.to_thread(get_gmail_service)
    msg = await asyncio.to_thread(
        lambda: service.users().messages().get(
            userId="me", id=message_id, format="full"
        ).execute()
    )
    metadata = extract_metadata(msg)
    attachments = extract_attachment_metadata(msg.get("payload", {}))

    grant = await asyncio.to_thread(get_active_grant_for_message, message_id)

    if not grant:
        audit({
            "action": "metadata_read",
            "messageId": message_id,
            "subject": metadata.get("subject", ""),
            "grant": "level0",
        })
        return {
            "metadata": metadata,
            "attachments": [
                {k: v for k, v in a.items() if k != "attachmentId"}
                for a in attachments
            ],
            "access": "metadata_only",
            "body": None,
            "hint": "POST /api/grants/request to request read access.",
        }

    # Check sensitive patterns
    sensitive_match = is_sensitive(
        metadata.get("subject", ""), metadata.get("from", "")
    )
    if sensitive_match and not (grant["level"] == 3 and override_sensitive):
        audit({
            "action": "message_redacted",
            "messageId": message_id,
            "grant": grant["id"],
            "pattern": sensitive_match,
        })
        return {
            "metadata": metadata,
            "access": f"level{grant['level']}",
            "grant": grant["id"],
            "body": f"[REDACTED — matches sensitive pattern: {sensitive_match}]",
            "sensitive": True,
        }

    body = extract_body(msg.get("payload", {}))

    # Level 1 is single-read — consume the grant
    if grant["level"] == 1:
        conn = db_conn()
        try:
            conn.execute("UPDATE grants SET status='consumed' WHERE id=?", (grant["id"],))
            conn.commit()
        finally:
            conn.close()

    audit({
        "action": "message_read",
        "messageId": message_id,
        "subject": metadata.get("subject", ""),
        "grant": grant["id"],
        "level": grant["level"],
    })

    return {
        "metadata": metadata,
        "attachments": attachments,
        "access": f"level{grant['level']}",
        "grant": grant["id"],
        "body": body,
    }

# ─── API: Attachments ────────────────────────────────────────────────────────


@app.get("/api/emails/{message_id}/attachments")
async def list_attachments(message_id: str):
    """List attachment metadata for a message (Level 0, no content)."""
    service = await asyncio.to_thread(get_gmail_service)
    msg = await asyncio.to_thread(
        lambda: service.users().messages().get(
            userId="me", id=message_id, format="full"
        ).execute()
    )
    attachments = extract_attachment_metadata(msg.get("payload", {}))
    audit({
        "action": "attachments_list",
        "messageId": message_id,
        "count": len(attachments),
    })
    return {"messageId": message_id, "attachments": attachments}


@app.get("/api/emails/{message_id}/attachments/{attachment_id}")
async def download_attachment(
    message_id: str,
    attachment_id: str,
    override_sensitive: bool = False,
):
    """Download an attachment. Requires a grant covering the parent message.

    Accepts consumed Level 1 grants (within expiry window) so you can read
    the body and then download attachments in the same session.
    """
    # Check grant (include_consumed=True for L1 attachment access after body read)
    grant = await asyncio.to_thread(
        get_active_grant_for_message, message_id, True
    )
    if not grant:
        raise HTTPException(
            403,
            "No active grant covers this message. POST /api/grants/request first.",
        )

    # Check sensitive patterns on parent message
    service = await asyncio.to_thread(get_gmail_service)
    msg = await asyncio.to_thread(
        lambda: service.users().messages().get(
            userId="me", id=message_id, format="metadata",
            metadataHeaders=["From", "Subject"],
        ).execute()
    )
    metadata = extract_metadata(msg)
    sensitive_match = is_sensitive(
        metadata.get("subject", ""), metadata.get("from", "")
    )
    if sensitive_match and not (grant["level"] == 3 and override_sensitive):
        raise HTTPException(
            403,
            f"Attachment blocked — parent message matches sensitive pattern: {sensitive_match}",
        )

    # Fetch the attachment
    att = await asyncio.to_thread(
        lambda: service.users().messages().attachments().get(
            userId="me", messageId=message_id, id=attachment_id
        ).execute()
    )
    data = base64.urlsafe_b64decode(att["data"])

    # Determine filename and mime type from message parts
    full_msg = await asyncio.to_thread(
        lambda: service.users().messages().get(
            userId="me", id=message_id, format="full"
        ).execute()
    )
    parts = extract_attachment_metadata(full_msg.get("payload", {}))
    filename = "attachment"
    mime_type = "application/octet-stream"
    for p in parts:
        if p["attachmentId"] == attachment_id:
            filename = p["filename"] or filename
            mime_type = p["mimeType"]
            break

    audit({
        "action": "attachment_download",
        "messageId": message_id,
        "attachmentId": attachment_id,
        "filename": filename,
        "size": len(data),
        "grant": grant["id"],
        "level": grant["level"],
    })

    # Sanitize filename to prevent header injection
    safe_filename = filename.replace('"', '_').replace('\r', '').replace('\n', '').replace('\x00', '')

    return Response(
        content=data,
        media_type=mime_type,
        headers={"Content-Disposition": f'attachment; filename="{safe_filename}"'},
    )

# ─── API: Threads ────────────────────────────────────────────────────────────


@app.get("/api/threads")
async def list_threads(
    q: str = "",
    maxResults: int = Query(default=20, le=100),
    labelIds: Optional[str] = None,
    pageToken: Optional[str] = None,
):
    """List/search threads — Level 0, metadata only."""
    service = await asyncio.to_thread(get_gmail_service)

    kwargs: dict = {"userId": "me", "maxResults": maxResults}
    if q:
        kwargs["q"] = q
    if labelIds:
        kwargs["labelIds"] = labelIds.split(",")
    if pageToken:
        kwargs["pageToken"] = pageToken

    results = await asyncio.to_thread(
        lambda: service.users().threads().list(**kwargs).execute()
    )

    threads = []
    for t in results.get("threads", []):
        threads.append({
            "id": t["id"],
            "historyId": t.get("historyId", ""),
        })

    audit({
        "action": "thread_list",
        "query": q or "(all)",
        "results": len(threads),
    })

    return {
        "threads": threads,
        "nextPageToken": results.get("nextPageToken"),
        "resultSizeEstimate": results.get("resultSizeEstimate", 0),
    }


@app.get("/api/threads/{thread_id}")
async def get_thread(thread_id: str, override_sensitive: bool = False):
    """Get all messages in a thread.

    Metadata is always returned. Bodies are included only for messages covered
    by an active grant. Does not consume Level 1 grants.
    """
    service = await asyncio.to_thread(get_gmail_service)
    thread = await asyncio.to_thread(
        lambda: service.users().threads().get(
            userId="me", id=thread_id, format="full"
        ).execute()
    )

    messages_out = []
    for msg in thread.get("messages", []):
        metadata = extract_metadata(msg)
        grant = await asyncio.to_thread(
            get_active_grant_for_message, msg["id"], True
        )

        if not grant:
            messages_out.append({
                "metadata": metadata,
                "access": "metadata_only",
                "body": None,
            })
            continue

        sensitive_match = is_sensitive(
            metadata.get("subject", ""), metadata.get("from", "")
        )
        if sensitive_match and not (grant["level"] == 3 and override_sensitive):
            messages_out.append({
                "metadata": metadata,
                "access": f"level{grant['level']}",
                "grant": grant["id"],
                "body": f"[REDACTED — matches sensitive pattern: {sensitive_match}]",
                "sensitive": True,
            })
            continue

        body = extract_body(msg.get("payload", {}))
        attachments = extract_attachment_metadata(msg.get("payload", {}))
        messages_out.append({
            "metadata": metadata,
            "attachments": attachments,
            "access": f"level{grant['level']}",
            "grant": grant["id"],
            "body": body,
        })

    bodies_returned = sum(1 for m in messages_out if m.get("body") is not None)
    audit({
        "action": "thread_read",
        "threadId": thread_id,
        "messageCount": len(messages_out),
        "bodiesReturned": bodies_returned,
    })

    return {
        "id": thread_id,
        "messages": messages_out,
    }

# ─── API: History / Sync ────────────────────────────────────────────────────


@app.get("/api/history")
async def get_history(
    startHistoryId: str = Query(..., description="History ID to start from"),
    historyTypes: Optional[str] = Query(
        default=None,
        description="Comma-separated: messageAdded,messageDeleted,labelAdded,labelRemoved",
    ),
    labelId: Optional[str] = None,
    maxResults: int = Query(default=100, le=500),
    pageToken: Optional[str] = None,
):
    """Incremental history since a given historyId. Requires Level 2+ grant.

    Use GET /api/profile to get the current historyId as a starting point.
    """
    # History exposes message changes — require at least a Level 2 or 3 grant
    now = datetime.now(timezone.utc).isoformat()
    conn = db_conn()
    try:
        grant = conn.execute(
            "SELECT * FROM grants WHERE status='active' AND level>=2 AND expires_at>?",
            (now,),
        ).fetchone()
    finally:
        conn.close()

    if not grant:
        raise HTTPException(
            403,
            "History requires an active Level 2+ grant. POST /api/grants/request first.",
        )
    grant = dict(grant)

    service = await asyncio.to_thread(get_gmail_service)
    kwargs: dict = {
        "userId": "me",
        "startHistoryId": startHistoryId,
        "maxResults": maxResults,
    }
    if historyTypes:
        kwargs["historyTypes"] = historyTypes.split(",")
    if labelId:
        kwargs["labelId"] = labelId
    if pageToken:
        kwargs["pageToken"] = pageToken

    try:
        result = await asyncio.to_thread(
            lambda: service.users().history().list(**kwargs).execute()
        )
    except Exception as e:
        error_str = str(e)
        if "404" in error_str or "notFound" in error_str:
            raise HTTPException(
                404,
                "startHistoryId is too old or invalid. Get a fresh one from GET /api/profile.",
            )
        raise

    audit({
        "action": "history_list",
        "startHistoryId": startHistoryId,
        "grant": grant["id"],
        "level": grant["level"],
        "records": len(result.get("history", [])),
    })

    return {
        "history": result.get("history", []),
        "nextPageToken": result.get("nextPageToken"),
        "historyId": result.get("historyId", ""),
    }

# ─── API: Grant Management ───────────────────────────────────────────────────

MAX_GRANT_DURATION_MINUTES = 1440  # 24 hours


class GrantRequest(BaseModel):
    model_config = {"extra": "ignore"}
    level: int  # 1, 2, or 3
    messageId: Optional[str] = None
    query: Optional[str] = None
    description: str
    durationMinutes: Optional[int] = None
    callback: bool = True  # Set to false to suppress callback on approval/denial
    callbackSessionKey: Optional[str] = None  # Session key to include in callback payload


@app.post("/api/grants/request")
async def request_grant(req: GrantRequest):
    """Request elevated access. Sends approval via Signal (link + reply code)."""
    # Rate limiting
    now_mono = time.monotonic()
    max_per_min = CONFIG.get("rate_limit", {}).get("grant_requests_per_minute", 5)
    while _grant_request_times and _grant_request_times[0] < now_mono - 60:
        _grant_request_times.popleft()
    if len(_grant_request_times) >= max_per_min:
        raise HTTPException(429, "Rate limit exceeded. Try again later.")
    _grant_request_times.append(now_mono)

    defaults = CONFIG.get("defaults", {})

    if req.level not in (1, 2, 3):
        raise HTTPException(400, "level must be 1, 2, or 3")
    if req.level == 1 and not req.messageId:
        raise HTTPException(400, "Level 1 requires messageId")
    if req.level == 2 and not req.query:
        raise HTTPException(400, "Level 2 requires query")

    # Determine duration (defaults are short, but caller can request up to 24h)
    if req.level == 1:
        default_dur = defaults.get("level1_expiry_minutes", 5)
        duration = min(req.durationMinutes or default_dur, MAX_GRANT_DURATION_MINUTES)
    elif req.level == 2:
        default_dur = defaults.get("level2_default_duration_minutes", 30)
        duration = min(req.durationMinutes or default_dur, MAX_GRANT_DURATION_MINUTES)
    else:
        default_dur = defaults.get("level3_default_duration_minutes", 15)
        duration = min(req.durationMinutes or default_dur, MAX_GRANT_DURATION_MINUTES)

    grant_id = f"g_{secrets.token_hex(8)}"
    approval_token = secrets.token_urlsafe(32)
    signal_code = secrets.token_hex(3).upper()  # e.g. "A1B2C3"
    now = datetime.now(timezone.utc)

    # Fetch message metadata for Level 1 approval message
    subject_line = ""
    sender = ""
    if req.messageId:
        try:
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
            subject_line = meta.get("subject", "")
            sender = meta.get("from", "")
        except Exception as e:
            log.warning("Could not fetch message metadata for grant request: %s", e)

    meta_dict = {
        "subject": subject_line,
        "sender": sender,
        "callback": req.callback,
        "callbackSessionKey": req.callbackSessionKey,
    }

    conn = db_conn()
    try:
        conn.execute(
            "INSERT INTO grants "
            "(id, level, status, message_id, query, description, "
            "approval_token, signal_code, created_at, duration_minutes, metadata) "
            "VALUES (?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?)",
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
            ),
        )
        conn.commit()
    finally:
        conn.close()

    approval_url = f"{CONFIG['approval_url_base']}/approve/{approval_token}"

    # Format duration for display
    if duration >= 60:
        dur_display = f"{duration // 60}h{duration % 60:02d}m" if duration % 60 else f"{duration // 60}h"
    else:
        dur_display = f"{duration} min"

    agent_name = CONFIG.get("agent_name", "Agent")

    # Compose Signal message with both approval URL and reply code
    if req.level == 1:
        signal_msg = (
            f"\U0001f4e7 {agent_name} wants to read:\n"
            f"From: {sender}\n"
            f"Subject: {subject_line}\n\n"
            f"Reply YES-{signal_code} or tap:\n{approval_url}\n"
            f"(expires in {dur_display})"
        )
    elif req.level == 2:
        signal_msg = (
            f"\U0001f4e7 {agent_name} requests read access:\n"
            f"{req.description}\n"
            f"Query: {req.query}\n"
            f"Duration: {dur_display}\n\n"
            f"Reply YES-{signal_code} or tap:\n{approval_url}"
        )
    else:
        signal_msg = (
            f"\U0001f513 {agent_name} requests FULL email read access\n"
            f"Reason: {req.description}\n"
            f"Duration: {dur_display}\n\n"
            f"Reply YES-{signal_code} or tap:\n{approval_url}"
        )

    await send_signal_message(signal_msg)

    audit({
        "action": "grant_requested",
        "grantId": grant_id,
        "level": req.level,
        "messageId": req.messageId,
        "query": req.query,
        "description": req.description,
        "durationMinutes": duration,
        "status": "pending",
    })

    return {
        "grantId": grant_id,
        "status": "pending",
        "level": req.level,
        "durationMinutes": duration,
        "message": f"Approval request sent. Poll GET /api/grants/{grant_id} for status.",
    }


GRANT_PUBLIC_FIELDS = (
    "id", "level", "status", "message_id", "query", "description",
    "created_at", "approved_at", "expires_at", "duration_minutes",
)


def _sanitize_grant(row: dict) -> dict:
    """Strip sensitive fields (approval_token, signal_code, metadata) before returning to callers."""
    return {k: row[k] for k in GRANT_PUBLIC_FIELDS if k in row}


@app.get("/api/grants/active")
async def list_active_grants():
    now = datetime.now(timezone.utc).isoformat()
    conn = db_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM grants WHERE status='active' "
            "AND (expires_at IS NULL OR expires_at>?)",
            (now,),
        ).fetchall()
    finally:
        conn.close()
    return {"grants": [_sanitize_grant(dict(r)) for r in rows]}


@app.get("/api/grants/{grant_id}")
async def get_grant(grant_id: str):
    conn = db_conn()
    try:
        row = conn.execute("SELECT * FROM grants WHERE id=?", (grant_id,)).fetchone()
    finally:
        conn.close()
    if not row:
        raise HTTPException(404, "Grant not found")
    return _sanitize_grant(dict(row))


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

# ─── API: Audit Log ──────────────────────────────────────────────────────────


@app.get("/api/audit")
async def get_audit(
    since: Optional[str] = None,
    limit: int = Query(default=50, le=500),
):
    since_dt = None
    if since:
        try:
            since_dt = datetime.fromisoformat(since)
        except ValueError:
            raise HTTPException(400, "Invalid 'since' timestamp format")

    entries: list[dict] = []
    if AUDIT_LOG_PATH.exists():
        with open(AUDIT_LOG_PATH) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if since_dt:
                    try:
                        entry_dt = datetime.fromisoformat(entry.get("ts", ""))
                        if entry_dt <= since_dt:
                            continue
                    except (ValueError, TypeError):
                        continue
                entries.append(entry)
    entries.reverse()
    return {"entries": entries[:limit]}

# ─── Approval URL Pages ──────────────────────────────────────────────────────

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
    """Generate and store a CSRF token for the given approval token."""
    # Clean up expired tokens
    now_mono = time.monotonic()
    expired_keys = [k for k, (_, exp) in _csrf_tokens.items() if exp < now_mono]
    for k in expired_keys:
        _csrf_tokens.pop(k, None)

    csrf_token = secrets.token_urlsafe(32)
    _csrf_tokens[approval_token] = (csrf_token, now_mono + 600)  # 10 min expiry
    return csrf_token


def _validate_csrf_token(approval_token: str, csrf_token: str) -> bool:
    """Validate and consume a CSRF token."""
    stored = _csrf_tokens.pop(approval_token, None)
    if not stored:
        return False
    expected, expiry = stored
    if time.monotonic() > expiry:
        return False
    return hmac.compare_digest(csrf_token, expected)


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
                "Email Proxy",
                f'<h1>Email Access Request</h1><div class="status">{label}</div>',
            )
        )

    meta = json.loads(grant.get("metadata") or "{}")
    agent_name = CONFIG.get("agent_name", "Agent")
    csrf_token = _issue_csrf_token(token)

    if grant["level"] == 1:
        details = (
            f"<p><strong>Type:</strong> Single message read</p>"
            f"<p><strong>From:</strong> {escape(meta.get('sender', 'Unknown'))}</p>"
            f"<p><strong>Subject:</strong> {escape(meta.get('subject', 'Unknown'))}</p>"
            f"<p><strong>Expires:</strong> {grant['duration_minutes']} min after approval</p>"
        )
    elif grant["level"] == 2:
        details = (
            f"<p><strong>Type:</strong> Scoped query access</p>"
            f"<p><strong>Query:</strong> <code>{escape(grant.get('query', ''))}</code></p>"
            f"<p><strong>Description:</strong> {escape(grant.get('description', ''))}</p>"
            f"<p><strong>Duration:</strong> {grant['duration_minutes']} min</p>"
        )
    else:
        details = (
            f"<p><strong>Type:</strong> FULL email read access</p>"
            f"<p><strong>Description:</strong> {escape(grant.get('description', ''))}</p>"
            f"<p><strong>Duration:</strong> {grant['duration_minutes']} min</p>"
        )

    body = (
        f"<h1>Email Access Request</h1>"
        f'<div class="card">'
        f"<p><strong>Level {grant['level']}</strong> — Requested by {escape(agent_name)}</p>"
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
                "Email Proxy",
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
        await fire_grant_callback(grant, "active", expires_at.isoformat())
    else:
        deny_grant(grant, via="url")
        result_body = "<h1>Denied</h1><p>Access request has been denied.</p>"
        await fire_grant_callback(grant, "denied")

    return HTMLResponse(_approval_html("Email Proxy", result_body))

# ─── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=CONFIG.get("port", 18795),
        log_level="info",
    )
