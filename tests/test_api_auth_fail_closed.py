"""Regression tests for API auth fail-closed behavior."""

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from gateway.middleware import check_api_key


def _client_with_api_middleware(monkeypatch, api_keys):
    """Build a tiny app using the real API-key middleware."""
    from gateway import app as app_mod

    monkeypatch.setattr(app_mod, "_api_keys", dict(api_keys))

    app = FastAPI()
    app.middleware("http")(check_api_key)

    @app.get("/api/test")
    async def api_test(request: Request):
        return {"requestor": request.state.requestor_name}

    @app.get("/health")
    async def health(request: Request):
        requestor = getattr(request.state, "requestor_name", None)
        return {"ok": True, "requestor": requestor}

    return TestClient(app)


def test_api_routes_fail_closed_when_no_api_keys_loaded(monkeypatch):
    client = _client_with_api_middleware(monkeypatch, {})

    response = client.get("/api/test")

    assert response.status_code == 503
    assert response.json() == {"detail": "API authentication unavailable"}


def test_api_routes_require_bearer_token_when_api_keys_loaded(monkeypatch):
    client = _client_with_api_middleware(monkeypatch, {"secret-token": "TestAgent"})

    response = client.get("/api/test")

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid or missing API key"}


def test_api_routes_reject_wrong_bearer_token(monkeypatch):
    client = _client_with_api_middleware(monkeypatch, {"secret-token": "TestAgent"})

    response = client.get("/api/test", headers={"Authorization": "Bearer wrong"})

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid or missing API key"}


def test_api_routes_accept_correct_bearer_token_and_set_requestor(monkeypatch):
    client = _client_with_api_middleware(monkeypatch, {"secret-token": "TestAgent"})

    response = client.get("/api/test", headers={"Authorization": "Bearer secret-token"})

    assert response.status_code == 200
    assert response.json() == {"requestor": "TestAgent"}


def test_non_api_routes_still_pass_without_api_keys(monkeypatch):
    client = _client_with_api_middleware(monkeypatch, {})

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"ok": True, "requestor": None}
