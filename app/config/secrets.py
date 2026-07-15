"""Async secret retrieval boundary with environment-backed default behavior."""

from __future__ import annotations

import os
from typing import Protocol


class SecretProvider(Protocol):
    """Retrieve configuration that may come from a future remote secret backend."""

    async def get(self, key: str) -> str | None:
        """Return the configured value, or None when the key does not exist."""
        ...


class EnvSecretProvider:
    """Read secrets from the process environment exactly when requested."""

    async def get(self, key: str) -> str | None:
        return os.getenv(key)


default_secret_provider: SecretProvider = EnvSecretProvider()
