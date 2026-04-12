"""Gmail resource provider — OAuth client, email helpers, and API routes."""

import asyncio
import base64
import json
import logging
from datetime import datetime, timezone
from email.utils import parseaddr
from fnmatch import fnmatch
from html import escape
from typing import Optional

from fastapi import FastAPI, HTTPException, Query

from gateway.audit import audit
from gateway.config import CONFIG, SENSITIVE
from gateway.db import db_conn
from gateway.vault import vault

log = logging.getLogger("gateway.providers.gmail")

# ── Gmail OAuth client ────────────────────────────────────────────────────

_gmail_service = None
_credentials = None


def get_gmail_service():
    """Get or refresh the authenticated Gmail API service."""
    from google.auth.transport.requests import Request as GoogleAuthRequest
    from google.oauth2.credentials import Credentials
    from googleapiclient.discovery import build

    global _gmail_service, _credentials

    if _credentials is not None and _credentials.valid:
        return _gmail_service

    if _credentials is not None and _credentials.expired and _credentials.refresh_token:
        _credentials.refresh(GoogleAuthRequest())
        try:
            vault.patch({"access_token": _credentials.token})
        except Exception as e:
            log.warning("Failed to persist refreshed access token to vault: %s", e)
        _gmail_service = build("gmail", "v1", credentials=_credentials, cache_discovery=False)
        return _gmail_service

    vault_secrets = vault.read_all()
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
            vault.patch({"access_token": _credentials.token})
        except Exception as e:
            log.warning("Failed to persist access token to vault: %s", e)

    _gmail_service = build("gmail", "v1", credentials=_credentials, cache_discovery=False)
    return _gmail_service


# ── Email helpers ─────────────────────────────────────────────────────────


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
    attachments: list[dict] = []

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


# ── Sensitive pattern matching ────────────────────────────────────────────


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


# ── Grant checking (Gmail-specific) ──────────────────────────────────────


def get_active_grant_for_message(
    message_id: str, include_consumed: bool = False,
) -> Optional[dict]:
    """Find an active, unexpired grant that covers this message."""
    now = datetime.now(timezone.utc).isoformat()
    conn = db_conn()
    try:
        # Level 1 — specific message
        if include_consumed:
            row = conn.execute(
                "SELECT * FROM grants WHERE status IN ('active','consumed') AND level=1 "
                "AND resource_type='gmail' AND message_id=? AND expires_at>?",
                (message_id, now),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT * FROM grants WHERE status='active' AND level=1 "
                "AND resource_type='gmail' AND message_id=? AND expires_at>?",
                (message_id, now),
            ).fetchone()
        if row:
            return dict(row)

        # Level 2 — query-based (verify message matches)
        rows = conn.execute(
            "SELECT * FROM grants WHERE status='active' AND level=2 "
            "AND resource_type='gmail' AND expires_at>?",
            (now,),
        ).fetchall()
        for row in rows:
            grant = dict(row)
            if _message_matches_query(message_id, grant["query"]):
                return grant

        # Level 3 — full access
        row = conn.execute(
            "SELECT * FROM grants WHERE status='active' AND level=3 "
            "AND resource_type='gmail' AND expires_at>?",
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


# ── Gmail Provider ────────────────────────────────────────────────────────


class GmailProvider:
    resource_type = "gmail"
    display_name = "Email"

    def validate_request(self, level: int, params: dict) -> Optional[str]:
        if level not in (1, 2, 3):
            return "level must be 1, 2, or 3"
        if level == 1 and not params.get("messageId"):
            return "Level 1 requires messageId"
        if level == 2 and not params.get("query"):
            return "Level 2 requires query"
        return None

    def default_duration(self, level: int) -> int:
        defaults = CONFIG.get("defaults", {})
        if level == 1:
            return defaults.get("level1_expiry_minutes", 5)
        if level == 2:
            return defaults.get("level2_default_duration_minutes", 30)
        return defaults.get("level3_default_duration_minutes", 15)

    def format_signal_notification(self, grant: dict, approval_url: str) -> str:
        agent_name = grant.get("requestor") or CONFIG.get("agent_name", "Agent")
        signal_code = grant["signal_code"]
        duration = grant["duration_minutes"]

        if duration >= 60:
            dur_display = f"{duration // 60}h{duration % 60:02d}m" if duration % 60 else f"{duration // 60}h"
        else:
            dur_display = f"{duration} min"

        meta = json.loads(grant.get("metadata") or "{}")
        sender = meta.get("sender", "")
        subject = meta.get("subject", "")

        if grant["level"] == 1:
            return (
                f"\U0001f4e7 {agent_name} wants to read:\n"
                f"From: {sender}\n"
                f"Subject: {subject}\n\n"
                f"Reply YES-{signal_code} or tap:\n{approval_url}\n"
                f"(expires in {dur_display})"
            )
        elif grant["level"] == 2:
            return (
                f"\U0001f4e7 {agent_name} requests read access:\n"
                f"{grant['description']}\n"
                f"Query: {grant.get('query', '')}\n"
                f"Duration: {dur_display}\n\n"
                f"Reply YES-{signal_code} or tap:\n{approval_url}"
            )
        else:
            return (
                f"\U0001f513 {agent_name} requests FULL email read access\n"
                f"Reason: {grant['description']}\n"
                f"Duration: {dur_display}\n\n"
                f"Reply YES-{signal_code} or tap:\n{approval_url}"
            )

    def format_approval_details(self, grant: dict) -> str:
        meta = json.loads(grant.get("metadata") or "{}")
        if grant["level"] == 1:
            return (
                f"<p><strong>Type:</strong> Single message read</p>"
                f"<p><strong>From:</strong> {escape(meta.get('sender', 'Unknown'))}</p>"
                f"<p><strong>Subject:</strong> {escape(meta.get('subject', 'Unknown'))}</p>"
                f"<p><strong>Expires:</strong> {grant['duration_minutes']} min after approval</p>"
            )
        elif grant["level"] == 2:
            return (
                f"<p><strong>Type:</strong> Scoped query access</p>"
                f"<p><strong>Query:</strong> <code>{escape(grant.get('query', ''))}</code></p>"
                f"<p><strong>Description:</strong> {escape(grant.get('description', ''))}</p>"
                f"<p><strong>Duration:</strong> {grant['duration_minutes']} min</p>"
            )
        else:
            return (
                f"<p><strong>Type:</strong> FULL email read access</p>"
                f"<p><strong>Description:</strong> {escape(grant.get('description', ''))}</p>"
                f"<p><strong>Duration:</strong> {grant['duration_minutes']} min</p>"
            )

    async def on_approved(self, grant: dict) -> None:
        pass

    async def on_revoked(self, grant: dict) -> None:
        pass

    async def startup(self) -> None:
        pass

    def register_routes(self, app: FastAPI) -> None:
        _register_gmail_routes(app)


# ── Gmail API routes ──────────────────────────────────────────────────────


def _register_gmail_routes(app: FastAPI):

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

    @app.get("/api/labels")
    async def list_labels():
        """List all Gmail labels with message/thread counts."""
        service = await asyncio.to_thread(get_gmail_service)
        result = await asyncio.to_thread(
            lambda: service.users().labels().list(userId="me").execute()
        )

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

        sensitive_match = is_sensitive(
            metadata.get("subject", ""), metadata.get("from", "")
        )
        if sensitive_match and not override_sensitive:
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
        """Download an attachment. Requires a grant covering the parent message."""
        from fastapi.responses import Response

        grant = await asyncio.to_thread(
            get_active_grant_for_message, message_id, True
        )
        if not grant:
            raise HTTPException(
                403,
                "No active grant covers this message. POST /api/grants/request first.",
            )

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
        if sensitive_match and not override_sensitive:
            raise HTTPException(
                403,
                f"Attachment blocked — parent message matches sensitive pattern: {sensitive_match}",
            )

        att = await asyncio.to_thread(
            lambda: service.users().messages().attachments().get(
                userId="me", messageId=message_id, id=attachment_id
            ).execute()
        )
        data = base64.urlsafe_b64decode(att["data"])

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

        safe_filename = filename.replace('"', '_').replace('\r', '').replace('\n', '').replace('\x00', '')

        return Response(
            content=data,
            media_type=mime_type,
            headers={"Content-Disposition": f'attachment; filename="{safe_filename}"'},
        )

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
        """Get all messages in a thread."""
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
            if sensitive_match and not override_sensitive:
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
        """Incremental history since a given historyId. Requires Level 2+ grant."""
        now = datetime.now(timezone.utc).isoformat()
        conn = db_conn()
        try:
            grant = conn.execute(
                "SELECT * FROM grants WHERE status='active' AND level>=2 "
                "AND resource_type='gmail' AND expires_at>?",
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
