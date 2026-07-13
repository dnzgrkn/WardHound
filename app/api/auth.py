"""Temporary static API-key authentication for the dashboard surface."""

from __future__ import annotations

import os
import secrets
from typing import Annotated

from fastapi import Header, HTTPException, status

API_KEY_ENV = "WARDHOUND_API_KEY"


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
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="WARDHOUND_API_KEY is not configured",
        )
    if not api_key_matches(api_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )
