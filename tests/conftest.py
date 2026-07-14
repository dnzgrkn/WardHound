"""Synthetic environment configuration shared by API tests."""

from __future__ import annotations

import os

os.environ.setdefault(
    "DATABASE_URL",
    "postgresql+asyncpg://wardhound:synthetic-test-password@localhost:5432/wardhound_test",
)
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("OTEL_SDK_DISABLED", "true")
