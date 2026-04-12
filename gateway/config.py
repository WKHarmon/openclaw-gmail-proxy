"""Configuration loading and constants."""

import json
import logging
import os
from pathlib import Path

log = logging.getLogger("gateway")

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = BASE_DIR / "config.json"
DATA_DIR = BASE_DIR / "data"
AUDIT_LOG_PATH = DATA_DIR / "audit.jsonl"
GRANTS_DB_PATH = DATA_DIR / "grants.db"

VAULT_ADDR = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
VAULT_ROLE_ID = os.environ.get("VAULT_ROLE_ID", "")
VAULT_SECRET_ID = os.environ.get("VAULT_SECRET_ID", "")
VAULT_ENABLED = bool(VAULT_ROLE_ID and VAULT_SECRET_ID)

MAX_GRANT_DURATION_MINUTES = 1440  # 24 hours


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


def get_requestors() -> dict[str, dict]:
    """Return the requestors map, normalizing from legacy single-agent config if needed.

    New format (config.json has "requestors" key):
        {"Lisa": {"api_key_vault_path": "...", "callback": {...}}, ...}

    Legacy format (config.json has "agent_name" + "vault_api_key_path" + "callback"):
        Auto-generates a single-entry requestors map.
    """
    if "requestors" in CONFIG:
        return CONFIG["requestors"]

    # Legacy single-agent config
    name = CONFIG.get("agent_name", "Agent")
    return {
        name: {
            "api_key_vault_path": CONFIG.get("vault_api_key_path", ""),
            "callback": CONFIG.get("callback"),
        }
    }
