from __future__ import annotations

import logging
from collections.abc import Sequence
from datetime import UTC, datetime

import pytest

from app.engines.digest import (
    DigestNarrativeGenerationError,
    create_digest_narrative_engine_from_env,
)
from app.engines.response import InMemoryApprovalStore
from app.schemas.digest import AggregateStat, DigestNarrative
from app.schemas.incidents import Incident
from app.stores.digest import InMemoryDigestStore
from app.stores.incidents import InMemoryEventStore, InMemoryIncidentStore
from app.tasks.digest import generate_daily_digest


class FailingNarrativeEngine:
    async def narrate(
        self, aggregate_stats: Sequence[AggregateStat], incidents: Sequence[Incident]
    ) -> DigestNarrative:
        raise DigestNarrativeGenerationError("Synthetic configured-provider failure")


async def test_scheduled_digest_without_key_persists_without_narrative(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    store = InMemoryDigestStore()

    digest = await generate_daily_digest(
        InMemoryEventStore(),
        InMemoryIncidentStore(),
        InMemoryApprovalStore(),
        store,
        create_digest_narrative_engine_from_env,
        period_end=datetime(2026, 7, 17, 12, tzinfo=UTC),
        delivery_client_factory=lambda: None,
    )

    assert digest.narrative is None
    assert await store.get(digest.id) == digest


async def test_narrative_failure_logs_and_persists_deterministic_digest(
    caplog: pytest.LogCaptureFixture,
) -> None:
    store = InMemoryDigestStore()
    caplog.set_level(logging.ERROR)

    digest = await generate_daily_digest(
        InMemoryEventStore(),
        InMemoryIncidentStore(),
        InMemoryApprovalStore(),
        store,
        FailingNarrativeEngine,
        period_end=datetime(2026, 7, 17, 12, tzinfo=UTC),
        delivery_client_factory=lambda: None,
    )

    assert digest.narrative is None
    assert await store.get(digest.id) == digest
    assert "Daily digest narrative generation failed" in caplog.text
