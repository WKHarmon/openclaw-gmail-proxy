"""SSH resource provider — OpenBao SSH CA integration and API routes."""

import json
import logging
from html import escape
from typing import Optional

from fastapi import FastAPI, HTTPException

from gateway.audit import audit
from gateway.config import CONFIG
from gateway.db import db_conn
from gateway.grants import get_active_grant
from gateway.models import SSHCredentialRequest
from gateway.vault import vault

log = logging.getLogger("gateway.providers.ssh")


def _ssh_config() -> dict:
    return CONFIG.get("providers", {}).get("ssh", {})


def _format_duration(minutes: int) -> str:
    if minutes >= 60:
        return f"{minutes // 60}h{minutes % 60:02d}m" if minutes % 60 else f"{minutes // 60}h"
    return f"{minutes} min"


class SSHProvider:
    resource_type = "ssh"
    display_name = "SSH"

    def validate_request(self, level: int, params: dict) -> Optional[str]:
        if level not in (1, 2, 3):
            return "level must be 1, 2, or 3"
        cfg = _ssh_config()
        hosts = cfg.get("hosts", {})
        host_groups = cfg.get("host_groups", {})

        principal = params.get("principal")
        if not principal:
            return "SSH access requires a principal"

        if level == 1:
            host = params.get("host")
            if not host:
                return "SSH Level 1 requires host"
            if host not in hosts:
                return f"Unknown host: {host}"
            allowed = hosts[host].get("principals", [])
            if principal not in allowed:
                return f"Principal '{principal}' not allowed on {host}"
        elif level == 2:
            host_group = params.get("hostGroup")
            if not host_group:
                return "SSH Level 2 requires hostGroup"
            if host_group not in host_groups:
                return f"Unknown host group: {host_group}"
        # Level 3: principal required (checked above), no host constraint

        return None

    def default_duration(self, level: int) -> int:
        defaults = _ssh_config().get("defaults", {})
        if level == 1:
            return defaults.get("level1_ttl_minutes", 30)
        if level == 2:
            return defaults.get("level2_ttl_minutes", 30)
        return defaults.get("level3_ttl_minutes", 30)

    def format_signal_notification(self, grant: dict, approval_url: str) -> str:
        agent_name = grant.get("requestor") or CONFIG.get("agent_name", "Agent")
        signal_code = grant["signal_code"]
        dur = _format_duration(grant["duration_minutes"])
        params = json.loads(grant.get("resource_params") or "{}")

        if grant["level"] == 1:
            return (
                f"\U0001f511 {agent_name} requests SSH access:\n"
                f"Host: {params.get('host', '?')}\n"
                f"Principal: {params.get('principal', '?')}\n"
                f"Reason: {grant['description']}\n"
                f"Duration: {dur}\n\n"
                f"Reply YES-{signal_code} or tap:\n{approval_url}"
            )
        elif grant["level"] == 2:
            return (
                f"\U0001f511 {agent_name} requests SSH group access:\n"
                f"Host group: {params.get('hostGroup', '?')}\n"
                f"Principal: {params.get('principal', '?')}\n"
                f"Reason: {grant['description']}\n"
                f"Duration: {dur}\n\n"
                f"Reply YES-{signal_code} or tap:\n{approval_url}"
            )
        else:
            return (
                f"\U0001f513 {agent_name} requests BROAD SSH access\n"
                f"Principal: {params.get('principal', '?')}\n"
                f"Reason: {grant['description']}\n"
                f"Duration: {dur}\n\n"
                f"Reply YES-{signal_code} or tap:\n{approval_url}"
            )

    def format_approval_details(self, grant: dict) -> str:
        params = json.loads(grant.get("resource_params") or "{}")
        if grant["level"] == 1:
            return (
                f"<p><strong>Type:</strong> SSH single-host certificate</p>"
                f"<p><strong>Host:</strong> {escape(params.get('host', '?'))}</p>"
                f"<p><strong>Principal:</strong> {escape(params.get('principal', '?'))}</p>"
                f"<p><strong>Description:</strong> {escape(grant.get('description', ''))}</p>"
                f"<p><strong>Expires:</strong> {grant['duration_minutes']} min after approval</p>"
            )
        elif grant["level"] == 2:
            return (
                f"<p><strong>Type:</strong> SSH host-group certificate</p>"
                f"<p><strong>Host group:</strong> {escape(params.get('hostGroup', '?'))}</p>"
                f"<p><strong>Principal:</strong> {escape(params.get('principal', '?'))}</p>"
                f"<p><strong>Description:</strong> {escape(grant.get('description', ''))}</p>"
                f"<p><strong>Duration:</strong> {grant['duration_minutes']} min</p>"
            )
        else:
            return (
                f"<p><strong>Type:</strong> SSH broad principal access</p>"
                f"<p><strong>Principal:</strong> {escape(params.get('principal', '?'))}</p>"
                f"<p><strong>Description:</strong> {escape(grant.get('description', ''))}</p>"
                f"<p><strong>Duration:</strong> {grant['duration_minutes']} min</p>"
            )

    async def on_approved(self, grant: dict) -> None:
        pass

    async def on_revoked(self, grant: dict) -> None:
        # SSH certs are self-expiring; no active revocation needed
        pass

    async def startup(self) -> None:
        cfg = _ssh_config()
        if cfg.get("enabled"):
            log.info(
                "SSH provider started (mount=%s, role=%s, %d hosts, %d groups)",
                cfg.get("vault_ssh_mount", "ssh-client-signer"),
                cfg.get("vault_ssh_role", "agent"),
                len(cfg.get("hosts", {})),
                len(cfg.get("host_groups", {})),
            )

    def register_routes(self, app: FastAPI) -> None:
        _register_ssh_routes(app)


# ── SSH API routes ────────────────────────────────────────────────────────


def _register_ssh_routes(app: FastAPI):

    @app.get("/api/ssh/hosts")
    async def list_ssh_hosts():
        """List configured SSH hosts and host groups (Level 0, always available)."""
        cfg = _ssh_config()
        hosts_out = {}
        for name, h in cfg.get("hosts", {}).items():
            hosts_out[name] = {
                "hostnames": h.get("hostnames", [name]),
                "principals": h.get("principals", []),
                "description": h.get("description", ""),
            }

        groups_out = {}
        for name, g in cfg.get("host_groups", {}).items():
            groups_out[name] = {
                "tag": g.get("tag", ""),
                "description": g.get("description", ""),
                "min_level": g.get("min_level", 2),
            }

        return {"hosts": hosts_out, "hostGroups": groups_out}

    @app.post("/api/ssh/credentials")
    async def issue_ssh_credentials(req: SSHCredentialRequest):
        """Issue a signed SSH certificate using an active SSH grant."""
        grant = get_active_grant(req.grantId)
        if not grant or grant.get("resource_type") != "ssh":
            raise HTTPException(403, "No active SSH grant with this ID")

        params = json.loads(grant.get("resource_params") or "{}")
        cfg = _ssh_config()
        mount = cfg.get("vault_ssh_mount", "ssh-client-signer")
        role = cfg.get("vault_ssh_role", "agent")
        principal = params.get("principal", "")

        if not principal:
            raise HTTPException(400, "Could not determine principal for this grant")

        # Cap TTL to the configured max
        max_ttl = cfg.get("max_ttl_minutes", 30)
        cert_ttl = min(grant["duration_minutes"], max_ttl)
        ttl = f"{cert_ttl}m"

        try:
            result = await vault.sign_ssh_key(
                mount=mount,
                role=role,
                public_key=req.publicKey,
                valid_principals=principal,
                ttl=ttl,
            )
        except Exception as e:
            log.error("SSH cert signing failed: %s", e)
            raise HTTPException(502, "Failed to sign SSH certificate")

        audit({
            "action": "ssh_cert_issued",
            "grantId": grant["id"],
            "host": params.get("host", ""),
            "principal": principal,
            "role": role,
            "serial": result.get("serial_number", ""),
        })

        # SSH grants are NOT consumed after a single use because certificates
        # are short-lived and must be renewed within the grant window.
        # The grant naturally expires via expires_at.

        return {
            "signedKey": result["signed_key"],
            "serial": result.get("serial_number", ""),
            "validBefore": grant["expires_at"],
        }
