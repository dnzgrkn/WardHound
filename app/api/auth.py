"""Static demo authentication and Auth0 identity for privileged API operations."""

from __future__ import annotations

import logging
import os
import secrets
from dataclasses import dataclass
from functools import lru_cache
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi_plugin.fast_api_client import Auth0FastAPI

API_KEY_ENV = "WARDHOUND_API_KEY"
AUTH0_DOMAIN_ENV = "AUTH0_DOMAIN"
AUTH0_AUDIENCE_ENV = "AUTH0_AUDIENCE"
REQUEST_ACTIONS_PERMISSION = "request:actions"
APPROVE_ACTIONS_PERMISSION = "approve:actions"
logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class Auth0Principal:
    """Verified Auth0 subject and API permissions extracted from an access token."""

    subject: str
    permissions: frozenset[str]


def configured_api_key() -> str | None:
    """Return the configured non-empty dashboard API key."""
    value = os.getenv(API_KEY_ENV)
    return value if value else None


def api_key_matches(provided: str | None) -> bool:
    """Compare a supplied key without leaking timing information."""
    expected = configured_api_key()
    return (
        expected is not None
        and provided is not None
        and secrets.compare_digest(provided, expected)
    )


def require_api_key(
    api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
) -> None:
    """Protect dashboard REST routes with the configured static API key."""
    if configured_api_key() is None:
        logger.error("API authentication unavailable", extra={"reason": "key_not_configured"})
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="WARDHOUND_API_KEY is not configured",
        )
    if not api_key_matches(api_key):
        logger.warning("API authentication rejected", extra={"reason": "invalid_or_missing_key"})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )


@lru_cache(maxsize=4)
def _auth0_client(domain: str, audience: str) -> Auth0FastAPI:
    return Auth0FastAPI(domain=domain, audience=audience, dpop_enabled=False)


async def require_auth0_principal(request: Request) -> Auth0Principal:
    """Validate an Auth0 Bearer token and return its attributable principal."""
    domain = os.getenv(AUTH0_DOMAIN_ENV, "").strip()
    audience = os.getenv(AUTH0_AUDIENCE_ENV, "").strip()
    if not domain or not audience:
        logger.error("Auth0 authentication unavailable", extra={"reason": "not_configured"})
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Auth0 identity is not configured",
        )
    claims = await _auth0_client(domain, audience).require_auth()(request)
    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Auth0 token is missing a subject",
            headers={"WWW-Authenticate": "Bearer"},
        )
    raw_permissions = claims.get("permissions", ())
    permissions = (
        frozenset(permission for permission in raw_permissions if isinstance(permission, str))
        if isinstance(raw_permissions, list)
        else frozenset()
    )
    return Auth0Principal(subject=subject, permissions=permissions)


def _require_permission(principal: Auth0Principal, permission: str) -> Auth0Principal:
    if permission not in principal.permissions:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Missing required permission: {permission}",
        )
    return principal


async def require_analyst(
    principal: Annotated[Auth0Principal, Depends(require_auth0_principal)],
) -> Auth0Principal:
    """Require an Auth0 principal allowed to request response actions."""
    return _require_permission(principal, REQUEST_ACTIONS_PERMISSION)


async def require_approver(
    principal: Annotated[Auth0Principal, Depends(require_auth0_principal)],
) -> Auth0Principal:
    """Require an Auth0 principal allowed to approve or reject response actions."""
    return _require_permission(principal, APPROVE_ACTIONS_PERMISSION)
