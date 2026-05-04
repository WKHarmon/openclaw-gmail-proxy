"""Regression tests for startup refusing to run without API keys."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


def test_lifespan_refuses_to_start_without_api_keys(monkeypatch):
    from gateway import app as app_mod

    monkeypatch.setattr(app_mod, "VAULT_ENABLED", False)
    monkeypatch.delenv("API_KEY", raising=False)
    app_mod._api_keys.clear()
    app_mod._requestor_callbacks.clear()

    test_app = FastAPI(lifespan=app_mod.lifespan)

    with pytest.raises(RuntimeError, match="No API keys loaded"):
        with TestClient(test_app):
            pass
