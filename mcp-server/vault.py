"""Lightweight Vault/OpenBao client for MCP server — AppRole auth + KV v2 read."""

import logging
import os
import time

import httpx

log = logging.getLogger("mcp-ssh.vault")


class VaultClient:
    """Minimal Vault client: AppRole login + KV v2 read."""

    def __init__(self):
        self._addr = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
        self._role_id = os.environ.get("VAULT_ROLE_ID", "")
        self._secret_id = os.environ.get("VAULT_SECRET_ID", "")
        self._enabled = bool(self._role_id and self._secret_id)
        self._token: str = ""
        self._token_expires: float = 0.0
        if self._enabled:
            self._http = httpx.Client(timeout=10.0)

    @property
    def enabled(self) -> bool:
        return self._enabled

    def _login(self):
        resp = self._http.post(
            f"{self._addr}/v1/auth/approle/login",
            json={"role_id": self._role_id, "secret_id": self._secret_id},
        )
        resp.raise_for_status()
        auth = resp.json()["auth"]
        self._token = auth["client_token"]
        lease = auth.get("lease_duration", 3600)
        self._token_expires = time.monotonic() + lease * 0.75
        log.info("Vault login successful (lease %ds)", lease)

    def _headers(self) -> dict:
        if not self._token or time.monotonic() >= self._token_expires:
            self._login()
        return {"X-Vault-Token": self._token}

    @staticmethod
    def _kv2_api_path(kv_path: str) -> str:
        parts = kv_path.split("/", 1)
        mount = parts[0]
        key = parts[1] if len(parts) > 1 else ""
        return f"{mount}/data/{key}"

    def read_secret(self, kv_path: str) -> dict:
        """Read from a KV v2 path. Returns the data dict."""
        if not self._enabled:
            raise RuntimeError("Vault not configured")
        api_path = self._kv2_api_path(kv_path)
        resp = self._http.get(
            f"{self._addr}/v1/{api_path}",
            headers=self._headers(),
        )
        resp.raise_for_status()
        return resp.json()["data"]["data"]
