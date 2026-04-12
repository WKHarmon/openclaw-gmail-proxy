"""HTTP client for the agent-authorization-gateway REST API."""

import logging

import httpx

log = logging.getLogger("mcp-ssh.gateway")


class GatewayClient:
    """Wraps the authorization gateway's SSH-related endpoints."""

    def __init__(self, base_url: str, api_key: str):
        self._base_url = base_url.rstrip("/")
        self._headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

    def _url(self, path: str) -> str:
        return f"{self._base_url}{path}"

    async def list_hosts(self) -> dict:
        """GET /api/ssh/hosts — list available hosts and host groups."""
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                self._url("/api/ssh/hosts"),
                headers=self._headers,
            )
            resp.raise_for_status()
            return resp.json()

    async def request_access(
        self,
        *,
        level: int = 1,
        host: str | None = None,
        principal: str,
        description: str,
        duration_minutes: int | None = None,
        host_group: str | None = None,
    ) -> dict:
        """POST /api/grants/request — request SSH access."""
        payload: dict = {
            "resourceType": "ssh",
            "level": level,
            "principal": principal,
            "description": description,
            "callback": False,
        }
        if host:
            payload["host"] = host
        if host_group:
            payload["hostGroup"] = host_group
        if duration_minutes:
            payload["durationMinutes"] = duration_minutes

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                self._url("/api/grants/request"),
                headers=self._headers,
                json=payload,
            )
            resp.raise_for_status()
            return resp.json()

    async def check_grant(self, grant_id: str) -> dict:
        """GET /api/grants/:id — check grant status."""
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                self._url(f"/api/grants/{grant_id}"),
                headers=self._headers,
            )
            resp.raise_for_status()
            return resp.json()

    async def list_active_grants(self) -> dict:
        """GET /api/grants/active?resourceType=ssh — list active SSH grants."""
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                self._url("/api/grants/active"),
                headers=self._headers,
                params={"resourceType": "ssh"},
            )
            resp.raise_for_status()
            return resp.json()

    async def get_credentials(self, grant_id: str, public_key: str) -> dict:
        """POST /api/ssh/credentials — issue a signed SSH certificate."""
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                self._url("/api/ssh/credentials"),
                headers=self._headers,
                json={"grantId": grant_id, "publicKey": public_key},
            )
            resp.raise_for_status()
            return resp.json()

    async def revoke_grant(self, grant_id: str) -> dict:
        """DELETE /api/grants/:id — revoke a grant."""
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.delete(
                self._url(f"/api/grants/{grant_id}"),
                headers=self._headers,
            )
            resp.raise_for_status()
            return resp.json()
