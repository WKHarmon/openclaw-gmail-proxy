"""Pydantic models for API requests."""

from typing import Optional

from pydantic import BaseModel


class GrantRequest(BaseModel):
    model_config = {"extra": "ignore"}

    resourceType: str = "gmail"
    level: int
    description: str
    durationMinutes: Optional[int] = None
    callback: bool = True
    callbackSessionKey: Optional[str] = None

    # Gmail-specific (kept at top level for backward compat)
    messageId: Optional[str] = None
    query: Optional[str] = None

    # SSH-specific
    host: Optional[str] = None
    principal: Optional[str] = None
    hostGroup: Optional[str] = None
    role: Optional[str] = None
    publicKey: Optional[str] = None

    # SSH-specific: explicit opt-in to bypass active-grant dedupe and request a
    # new grant even when a matching active one exists (e.g. when the remaining
    # duration is shorter than what you now need).
    allowReplaceShorterGrant: bool = False


class SSHCredentialRequest(BaseModel):
    """Request body for POST /api/ssh/credentials.

    Two calling modes:

    1. **By grantId** (classic): pass ``grantId`` and ``publicKey``. The
       endpoint mints a cert against that active grant.
    2. **By scope** (one-call): omit ``grantId`` and pass ``level`` +
       ``principal`` + one of ``host`` / ``hostGroup`` + ``description`` +
       ``publicKey``. The endpoint looks up an active matching grant; if
       found it mints a cert, if not it creates a new pending approval
       request and returns ``certificateIssued: false`` with the pending
       grantId.
    """

    model_config = {"extra": "ignore"}

    publicKey: str

    # Mode 1: explicit grant
    grantId: Optional[str] = None

    # Mode 2: scope-based lookup/create (used when grantId is omitted)
    level: Optional[int] = None
    host: Optional[str] = None
    hostGroup: Optional[str] = None
    principal: Optional[str] = None
    role: Optional[str] = None
    description: Optional[str] = None
    durationMinutes: Optional[int] = None
    allowReplaceShorterGrant: bool = False
    callback: bool = True
    callbackSessionKey: Optional[str] = None
