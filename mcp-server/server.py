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


def _ensure_keypair(public_key: str) -> tuple[str, str | None]:
    """Return a (public_key, ephemeral_key_path_or_None) tuple.

    If ``public_key`` is empty, generates an ephemeral ed25519 keypair under
    ``~/.cache/ssh-mcp`` and returns its public key + private-key path.
    """
    if public_key:
        return public_key, None
    base = Path.home() / ".cache" / "ssh-mcp"
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp_dir = tempfile.mkdtemp(dir=base)
    key_path = Path(tmp_dir) / "id_ed25519"
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-f", str(key_path), "-N", "", "-q"],
        check=True,
    )
    pub = (key_path.with_suffix(".pub")).read_text().strip()
    return pub, str(key_path)


def _write_cert_file(ephemeral_key_path: str, signed_key: str) -> str:
    cert_path = f"{ephemeral_key_path}-cert.pub"
    Path(cert_path).write_text(signed_key + "\n")
    return cert_path


async def _mint_certificate(grant_id: str, public_key: str) -> dict:
    """Issue a cert against an active grant (classic path).

    Generates an ephemeral ed25519 keypair when ``public_key`` is empty.
    Returns a structured result dict.
    """
    client = _get_client()
    public_key, ephemeral_key_path = _ensure_keypair(public_key)
    result = await client.get_credentials(grant_id, public_key)
    out = {
        "signedKey": result.get("signedKey", ""),
        "serial": result.get("serial", ""),
        "validBefore": result.get("validBefore", ""),
    }
    if ephemeral_key_path:
        out["privateKeyPath"] = ephemeral_key_path
        out["certificatePath"] = _write_cert_file(ephemeral_key_path, out["signedKey"])
    return out


@mcp.tool()
async def ssh_list_hosts() -> str:
    """List available SSH hosts and host groups with their allowed principals.

    Use this to discover what hosts you can request access to before calling
    ssh_ensure_credentials.
    """
    client = _get_client()
    result = await client.list_hosts()
    return json.dumps(result, indent=2)


@mcp.tool()
async def ssh_ensure_credentials(
    host: str,
    principal: str,
    description: str,
    level: int = 1,
    duration_minutes: int | None = None,
    host_group: str | None = None,
    public_key: str = "",
    allow_replace_shorter_grant: bool = False,
) -> str:
    """Get SSH credentials, reusing an active grant when possible.

    This is the DEFAULT way to obtain SSH access. It:
      1. Asks the gateway if an active matching SSH grant already exists.
      2. If yes: mints a fresh short-lived certificate from that grant and
         returns it. No approval prompt is sent.
      3. If no: sends a new approval request to the approver via Signal and
         returns a pending grant ID to poll/callback.

    If an active grant exists but its remaining duration is shorter than
    ``duration_minutes``, the grant is still reused and the response will
    include ``shorterThanRequested: true`` and ``durationSatisfied: false``.
    To explicitly request a new longer grant in that case, set
    ``allow_replace_shorter_grant=True``.

    Args:
        host: Target host (required for level 1).
        principal: SSH username for the certificate.
        description: Human-readable reason (shown to approver if approval is
            needed).
        level: 1=single host, 2=host group, 3=broad principal. Default 1.
        duration_minutes: Requested duration. Defaults vary by level.
        host_group: Host group name (required for level 2).
        public_key: SSH public key to sign. If empty, an ephemeral keypair
            is generated and the private-key path is returned.
        allow_replace_shorter_grant: If True and a matching active grant
            exists but is shorter than the requested duration, request a
            new longer grant instead of reusing the shorter one.
    """
    client = _get_client()

    # Prepare a keypair up-front (so the server can mint a cert in the same
    # round-trip when an active grant is reused).
    pub, ephemeral_key_path = _ensure_keypair(public_key)

    result = await client.get_credentials_for_scope(
        public_key=pub,
        level=level,
        principal=principal,
        description=description,
        host=host if level != 2 else None,
        host_group=host_group if level == 2 else None,
        duration_minutes=duration_minutes,
        allow_replace_shorter_grant=allow_replace_shorter_grant,
    )

    cert_issued = bool(result.get("certificateIssued"))
    out: dict = {
        "action": result.get("action"),
        "grantId": result.get("grantId"),
        "reused": bool(result.get("reused")),
        "certificateIssued": cert_issued,
        "status": result.get("status"),
    }

    if cert_issued:
        out["signedKey"] = result.get("signedKey", "")
        out["serial"] = result.get("serial", "")
        out["validBefore"] = result.get("validBefore", "")
        if ephemeral_key_path:
            cert_path = _write_cert_file(ephemeral_key_path, out["signedKey"])
            out["privateKeyPath"] = ephemeral_key_path
            out["certificatePath"] = cert_path

        # Reuse / duration metadata (may be absent if classic grantId path)
        for key in (
            "durationSatisfied", "shorterThanRequested",
            "requestedDurationSeconds", "remainingDurationSeconds", "expiresAt",
        ):
            if key in result:
                out[key] = result[key]

        if result.get("shorterThanRequested"):
            out["hint"] = (
                "The reused active grant is shorter than requested. If you "
                "need longer access, call ssh_ensure_credentials again with "
                "allow_replace_shorter_grant=true."
            )
    else:
        # No cert yet — a new pending approval was created.
        out["durationMinutes"] = result.get("durationMinutes")
        if result.get("previousGrantId"):
            out["previousGrantId"] = result["previousGrantId"]
        if result.get("action") == "requested_replacement_grant_due_to_short_duration":
            out["hint"] = (
                "Existing active grant was too short; a new approval request "
                f"was sent. Poll ssh_check_grant(grant_id=\"{out['grantId']}\") "
                f"or wait for the configured callback, then call "
                f"ssh_ensure_credentials again to mint a certificate."
            )
        else:
            out["hint"] = (
                "Approval request sent. Poll ssh_check_grant(grant_id="
                f"\"{out['grantId']}\") or wait for the configured callback, "
                f"then call ssh_ensure_credentials again to mint a certificate."
            )
        # Keep the pre-generated private key around — when the caller retries
        # after approval, passing the same public_key='' generates yet another
        # keypair. To avoid leaking tmp dirs we clean up the pending one here.
        if ephemeral_key_path:
            try:
                Path(ephemeral_key_path).unlink(missing_ok=True)
                Path(ephemeral_key_path + ".pub").unlink(missing_ok=True)
                Path(ephemeral_key_path).parent.rmdir()
            except OSError:
                pass

    return json.dumps(out, indent=2)


@mcp.tool()
async def ssh_request_new_grant(
    host: str,
    principal: str,
    description: str,
    level: int = 1,
    duration_minutes: int | None = None,
    host_group: str | None = None,
    allow_replace_shorter_grant: bool = False,
) -> str:
    """Low-level: force a new SSH grant approval request.

    PREFER ssh_ensure_credentials — it reuses active matching grants and
    avoids unnecessary approval prompts. Use this tool only when you know
    you need a brand-new approval flow (e.g. the existing active grant is
    shorter than the duration you now need, and you need an explicit
    replacement grant).

    If a matching active grant exists and ``allow_replace_shorter_grant`` is
    False (default), the gateway will still dedupe and return that active
    grant (with ``action='reused_active_grant'``) — this tool cannot bypass
    that guard unless you opt in via ``allow_replace_shorter_grant=True``.

    Args:
        host: Target host (required for level 1).
        principal: SSH username for the certificate.
        description: Human-readable reason (shown to approver).
        level: 1=single host, 2=host group, 3=broad principal. Default 1.
        duration_minutes: Requested duration. Defaults vary by level.
        host_group: Host group name (required for level 2).
        allow_replace_shorter_grant: Set True to bypass dedupe against an
            existing shorter active grant and force a fresh approval.
    """
    client = _get_client()
    result = await client.request_access(
        level=level,
        host=host if level != 2 else None,
        principal=principal,
        description=description,
        duration_minutes=duration_minutes,
        host_group=host_group if level == 2 else None,
        allow_replace_shorter_grant=allow_replace_shorter_grant,
    )
    return json.dumps(result, indent=2)


# Backward-compatible alias for ssh_request_new_grant. Calls the same backend
# path (which now dedupes automatically). Kept so existing agent scripts still
# work, but prefer ssh_ensure_credentials.
@mcp.tool()
async def ssh_request_access(
    host: str,
    principal: str,
    description: str,
    level: int = 1,
    duration_minutes: int | None = None,
    host_group: str | None = None,
) -> str:
    """DEPRECATED — use ssh_ensure_credentials.

    Kept as a backward-compatible alias for ssh_request_new_grant. The
    backend now dedupes against active matching grants automatically, so
    calling this tool will reuse an active grant when one exists rather
    than sending another approval prompt.
    """
    return await ssh_request_new_grant(
        host=host,
        principal=principal,
        description=description,
        level=level,
        duration_minutes=duration_minutes,
        host_group=host_group,
    )


@mcp.tool()
async def ssh_check_grant(grant_id: str) -> str:
    """Check the status of an SSH access grant.

    Args:
        grant_id: The grant ID returned by ssh_ensure_credentials or
            ssh_request_new_grant.
    """
    client = _get_client()
    result = await client.check_grant(grant_id)
    status = result.get("status", "unknown")
    lines = [f"Grant {grant_id}: {status}"]
    if status == "active":
        lines.append(f"Expires: {result.get('expires_at', '?')}")
        lines.append(
            f"\nGrant is active. Call ssh_ensure_credentials(...) with the "
            f"same host/principal to mint a fresh certificate — it will "
            f"reuse this grant automatically."
        )
    elif status == "pending":
        lines.append("Waiting for approver. Check again shortly.")
    elif status == "denied":
        lines.append("Access was denied by the approver.")
    elif status == "expired":
        lines.append("Grant has expired. Call ssh_ensure_credentials(...) to request a new one.")
    return "\n".join(lines)


@mcp.tool()
async def ssh_get_credentials(grant_id: str, public_key: str = "") -> str:
    """Mint a signed SSH certificate from an already-active grant.

    Most callers should use ssh_ensure_credentials instead — it handles
    grant lookup/reuse/request + cert issuance in one call. Use this tool
    only when you already have a specific active grantId (for example from
    an approval callback).

    Args:
        grant_id: The grant ID (must be in "active" status).
        public_key: SSH public key to sign. If empty, generates an ephemeral keypair.
    """
    cert = await _mint_certificate(grant_id, public_key)
    signed_key = cert["signedKey"]
    serial = cert["serial"]
    valid_before = cert["validBefore"]

    if "privateKeyPath" in cert:
        return (
            f"SSH certificate issued successfully.\n"
            f"Serial: {serial}\n"
            f"Valid until: {valid_before}\n\n"
            f"Private key: {cert['privateKeyPath']}\n"
            f"Certificate: {cert['certificatePath']}\n\n"
            f"Connect with:\n"
            f"  ssh -i {cert['privateKeyPath']} -o CertificateFile={cert['certificatePath']} <user>@<host>"
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
