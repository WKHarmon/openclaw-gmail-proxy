"""API key authentication middleware."""

import hmac

from fastapi import Request
from fastapi.responses import JSONResponse


async def check_api_key(request: Request, call_next):
    """Require Bearer token on /api/* routes. Identifies the requestor from the key."""
    from gateway.app import get_api_keys

    api_keys = get_api_keys()
    if api_keys and request.url.path.startswith("/api/"):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid or missing API key"},
            )
        token = auth[7:]
        # Constant-time comparison against all registered keys
        matched_requestor = None
        for key, name in api_keys.items():
            if hmac.compare_digest(token, key):
                matched_requestor = name
                break
        if matched_requestor is None:
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid or missing API key"},
            )
        request.state.requestor_name = matched_requestor
    else:
        request.state.requestor_name = None
    return await call_next(request)
