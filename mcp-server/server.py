"""MCP server for SSH access via the agent-authorization-gateway."""

import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from gateway_client import GatewayClient
from vault import VaultClient

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("mcp-ssh")

mcp = FastMCP("ssh-gateway")

# Initialized at startup
_client: GatewayClient | None = None


def _get_client() -> GatewayClient:
    global _client
    if _client is not None:
        return _client

    gateway_url = os.environ.get("GATEWAY_URL", "http://localhost:18795")

    # Try Vault first for API key
    api_key = os.environ.get("GATEWAY_API_KEY", "").strip()
    if not api_key:
        api_key_vault_path = os.environ.get(
            "GATEWAY_API_KEY_VAULT_PATH",
            "secret/claude-code/authorization-gateway",
        )
        vault = VaultClient()
        if vault.enabled:
            try:
                secret = vault.read_secret(api_key_vault_path)
                api_key = secret["api_key"].strip()
                log.info("Gateway API key loaded from Vault")
            except Exception as e:
                log.error("Failed to load API key from Vault: %s", e)
                raise RuntimeError(f"Cannot load API key from Vault: {e}") from e
        else:
            raise RuntimeError(
                "No GATEWAY_API_KEY set and Vault not configured "
                "(need VAULT_ADDR, VAULT_ROLE_ID, VAULT_SECRET_ID)"
            )

    _client = GatewayClient(gateway_url, api_key)
    return _client


@mcp.tool()
async def ssh_list_hosts() -> str:
    """List available SSH hosts and host groups with their allowed principals.

    Use this to discover what hosts you can request access to before calling
    ssh_request_access.
    """
    client = _get_client()
    result = await client.list_hosts()
    return json.dumps(result, indent=2)


@mcp.tool()
async def ssh_request_access(
    host: str,
    principal: str,
    description: str,
    level: int = 1,
    duration_minutes: int | None = None,
    host_group: str | None = None,
) -> str:
    """Request SSH access to a host. Sends an approval request to the approver's phone.

    Returns immediately with a grant ID and "pending" status. The approver must
    approve via Signal before you can get credentials. Use ssh_check_grant to
    poll for approval status.

    Args:
        host: Target host name (must match a configured host). Required for level 1.
        principal: SSH username for the certificate (e.g., "kyle", "claude").
        description: Human-readable reason for access (shown to approver).
        level: Access level (1=single host, 2=host group, 3=broad principal). Default 1.
        duration_minutes: Requested duration. Defaults vary by level.
        host_group: Host group name (required for level 2).
    """
    client = _get_client()
    result = await client.request_access(
        level=level,
        host=host if level != 2 else None,
        principal=principal,
        description=description,
        duration_minutes=duration_minutes,
        host_group=host_group if level == 2 else None,
    )
    grant_id = result.get("grantId", "")
    return (
        f"Approval request sent. Grant ID: {grant_id}\n"
        f"Status: {result.get('status', 'pending')}\n"
        f"Duration: {result.get('durationMinutes', '?')} minutes\n\n"
        f"The approver has been notified via Signal. "
        f"Use ssh_check_grant(grant_id=\"{grant_id}\") to check approval status."
    )


@mcp.tool()
async def ssh_check_grant(grant_id: str) -> str:
    """Check the status of an SSH access grant.

    Args:
        grant_id: The grant ID returned by ssh_request_access.
    """
    client = _get_client()
    result = await client.check_grant(grant_id)
    status = result.get("status", "unknown")
    lines = [f"Grant {grant_id}: {status}"]
    if status == "active":
        lines.append(f"Expires: {result.get('expires_at', '?')}")
        lines.append(f"\nGrant is active. Use ssh_get_credentials(grant_id=\"{grant_id}\") to get a signed certificate.")
    elif status == "pending":
        lines.append("Waiting for approver. Check again shortly.")
    elif status == "denied":
        lines.append("Access was denied by the approver.")
    elif status == "expired":
        lines.append("Grant has expired. Request a new one if needed.")
    return "\n".join(lines)


@mcp.tool()
async def ssh_get_credentials(grant_id: str, public_key: str = "") -> str:
    """Get a signed SSH certificate for an active grant.

    If no public_key is provided, generates an ephemeral ed25519 keypair
    and returns the private key path and signed certificate.

    Args:
        grant_id: The grant ID (must be in "active" status).
        public_key: SSH public key to sign. If empty, generates an ephemeral keypair.
    """
    client = _get_client()

    ephemeral_key_path = None
    if not public_key:
        # Generate ephemeral ed25519 keypair
        tmp_dir = tempfile.mkdtemp(prefix="ssh-mcp-")
        key_path = Path(tmp_dir) / "id_ed25519"
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-f", str(key_path), "-N", "", "-q"],
            check=True,
        )
        public_key = (key_path.with_suffix(".pub")).read_text().strip()
        ephemeral_key_path = str(key_path)

    result = await client.get_credentials(grant_id, public_key)

    signed_key = result.get("signedKey", "")
    serial = result.get("serial", "")
    valid_before = result.get("validBefore", "")

    if ephemeral_key_path:
        # Write the signed cert next to the private key
        cert_path = f"{ephemeral_key_path}-cert.pub"
        Path(cert_path).write_text(signed_key + "\n")
        return (
            f"SSH certificate issued successfully.\n"
            f"Serial: {serial}\n"
            f"Valid until: {valid_before}\n\n"
            f"Private key: {ephemeral_key_path}\n"
            f"Certificate: {cert_path}\n\n"
            f"Connect with:\n"
            f"  ssh -i {ephemeral_key_path} -o CertificateFile={cert_path} <user>@<host>"
        )
    else:
        return (
            f"SSH certificate issued successfully.\n"
            f"Serial: {serial}\n"
            f"Valid until: {valid_before}\n\n"
            f"Signed certificate:\n{signed_key}"
        )


@mcp.tool()
async def ssh_list_active_grants() -> str:
    """List all currently active SSH grants."""
    client = _get_client()
    result = await client.list_active_grants()
    grants = result.get("grants", [])
    if not grants:
        return "No active SSH grants."
    lines = []
    for g in grants:
        lines.append(
            f"- {g['id']}: Level {g['level']} "
            f"(expires {g.get('expires_at', '?')})"
        )
    return "\n".join(lines)


@mcp.tool()
async def ssh_revoke_grant(grant_id: str) -> str:
    """Revoke an SSH grant early.

    Note: SSH certificates are self-expiring, so revocation mainly prevents
    new certificates from being issued under this grant.

    Args:
        grant_id: The grant ID to revoke.
    """
    client = _get_client()
    result = await client.revoke_grant(grant_id)
    return f"Grant {grant_id} revoked. Status: {result.get('status', 'revoked')}"


if __name__ == "__main__":
    mcp.run()
