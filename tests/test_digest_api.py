"""API coverage for manual daily digest generation and history."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.api.realtime import IncidentConnectionManager
from app.api.services import AnalysisEngine, ApiServices, get_api_services
from app.engines.digest import DigestNarrativeGenerationError
from app.engines.response import InMemoryApprovalStore, ResponseEngine
from app.main import create_app
from app.schemas.digest import AggregateStat, DigestNarrative
from app.schemas.events import (
    EntityType,
    NormalizedEntity,
    NormalizedEvent,
    NormalizedEventType,
    Severity,
    SourceSystem,
)
from app.schemas.incidents import Incident
from app.stores.digest import InMemoryDigestStore
from app.stores.incidents import InMemoryEventStore, InMemoryIncidentStore

API_KEY = "synthetic-digest-api-key"
HEADERS = {"X-API-Key": API_KEY}


def unused_analysis_engine() -> AnalysisEngine:
    raise AssertionError("Incident analysis is not used by digest API tests")


class FailingDigestNarrativeEngine:
    async def narrate(
        self, aggregate_stats: Sequence[AggregateStat], incidents: Sequence[Incident]
    ) -> DigestNarrative:
        raise DigestNarrativeGenerationError("Synthetic digest narrative failure")


@pytest.fixture
def application(monkeypatch: pytest.MonkeyPatch) -> tuple[FastAPI, ApiServices]:
    monkeypatch.setenv("WARDHOUND_API_KEY", API_KEY)
    approvals = InMemoryApprovalStore()
    services = ApiServices(
        incidents=InMemoryIncidentStore(),
        events=InMemoryEventStore(),
        response_engine=ResponseEngine(approvals),
        analysis_engine_factory=unused_analysis_engine,
        connections=IncidentConnectionManager(),
        digests=InMemoryDigestStore(),
        digest_narrative_engine_factory=None,
    )
    app = create_app()
    app.dependency_overrides[get_api_services] = lambda: services
    return app, services


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/api/v1/digests/generate"),
        ("GET", "/api/v1/digests"),
        ("GET", f"/api/v1/digests/{uuid4()}"),
    ],
)
async def test_digest_routes_require_static_api_key(
    application: tuple[FastAPI, ApiServices], method: str, path: str
) -> None:
    app, _ = application
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.request(method, path)

    assert response.status_code == 401


async def test_generate_list_and_get_digest_history(
    application: tuple[FastAPI, ApiServices],
) -> None:
    app, services = application
    event = NormalizedEvent(
        raw_event_id=uuid4(),
        source_system=SourceSystem.ACTIVE_DIRECTORY,
        event_type=NormalizedEventType.AUTH_FAILED,
        severity=Severity.MEDIUM,
        primary_entity=NormalizedEntity(
            entity_type=EntityType.USER,
            username="synthetic-api-user",
        ),
        occurred_at=datetime.now(UTC),
    )
    await services.events.add_all([event])

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        first = await client.post("/api/v1/digests/generate", headers=HEADERS)
        second = await client.post("/api/v1/digests/generate", headers=HEADERS)
        history = await client.get("/api/v1/digests", headers=HEADERS)
        detail = await client.get(
            f"/api/v1/digests/{first.json()['id']}", headers=HEADERS
        )
        missing = await client.get(f"/api/v1/digests/{uuid4()}", headers=HEADERS)

    assert first.status_code == 201
    assert second.status_code == 201
    assert first.json()["narrative"] is None
    assert any(
        stat["name"] == "failed_authentication_by_user" and stat["count"] == 1
        for stat in first.json()["aggregate_stats"]
    )
    assert history.status_code == 200
    assert [item["id"] for item in history.json()[:2]] == [
        second.json()["id"],
        first.json()["id"],
    ]
    assert detail.status_code == 200
    assert detail.json()["id"] == first.json()["id"]
    assert missing.status_code == 404
    assert missing.json()["code"] == "digest_not_found"


async def test_digest_narrative_generation_failure_returns_typed_502(
    application: tuple[FastAPI, ApiServices],
) -> None:
    app, services = application
    failing_services = ApiServices(
        incidents=services.incidents,
        events=services.events,
        response_engine=services.response_engine,
        analysis_engine_factory=services.analysis_engine_factory,
        connections=services.connections,
        digests=services.digests,
        digest_narrative_engine_factory=FailingDigestNarrativeEngine,
    )
    app.dependency_overrides[get_api_services] = lambda: failing_services

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.post("/api/v1/digests/generate", headers=HEADERS)

    assert response.status_code == 502
    assert response.json()["code"] == "digest_narrative_generation_failed"
