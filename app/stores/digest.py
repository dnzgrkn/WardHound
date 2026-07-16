"""Async persistence port and in-memory implementation for daily digests."""

from __future__ import annotations

from typing import Protocol
from uuid import UUID

from app.schemas.digest import DailyDigest


class DigestStore(Protocol):
    """Persistence port for immutable generated daily digests."""

    async def append(self, digest: DailyDigest) -> None:
        """Persist one generated digest by UUID."""
        ...

    async def get(self, digest_id: UUID) -> DailyDigest | None:
        """Return one digest by UUID, if retained."""
        ...

    async def list_recent(self, limit: int) -> list[DailyDigest]:
        """Return at most ``limit`` digests, newest generation first."""
        ...


class InMemoryDigestStore:
    """Dict-backed digest history for isolated tests and local composition."""

    def __init__(self) -> None:
        self._digests: dict[UUID, DailyDigest] = {}

    async def append(self, digest: DailyDigest) -> None:
        self._digests[digest.id] = digest

    async def get(self, digest_id: UUID) -> DailyDigest | None:
        return self._digests.get(digest_id)

    async def list_recent(self, limit: int) -> list[DailyDigest]:
        if limit <= 0:
            return []
        return sorted(
            self._digests.values(),
            key=lambda digest: (digest.generated_at, str(digest.id)),
            reverse=True,
        )[:limit]
