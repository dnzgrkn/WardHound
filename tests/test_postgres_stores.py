"""Integration coverage for repositories backed by a real PostgreSQL server."""

from __future__ import annotations

import asyncio
import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool

from app.db.models import IncidentRecord, NormalizedEventRecord, ResponseActionAuditRecord
from app.engines.response import ApprovalStore
from app.schemas.analysis import Evidence, RecommendedAction, ResponseActionType, RootCauseAnalysis
from app.schemas.events import (
    EntityType,
    NormalizedEntity,
    NormalizedEvent,
    NormalizedEventType,
    Severity,
    SourceSystem,
)
from app.schemas.incidents import Incident
from app.schemas.response import ActionAuditRecord, ApprovalStatus
from app.stores.incidents import EventStore, IncidentStore
from app.stores.postgres import (
    PostgresApprovalStore,
    PostgresEventStore,
    PostgresIncidentStore,
)


@pytest.fixture(scope="module")
def postgres_engine() -> Iterator[AsyncEngine]:
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        pytest.skip("DATABASE_URL is not configured")
    engine = create_async_engine(database_url, poolclass=NullPool)

    async def reachable() -> None:
        async with engine.connect() as connection:
            await connection.execute(text("SELECT 1"))

    try:
        asyncio.run(reachable())
    except (OSError, SQLAlchemyError) as exc:
        asyncio.run(engine.dispose())
        pytest.skip(f"PostgreSQL is not reachable: {type(exc).__name__}")

    command.upgrade(Config("alembic.ini"), "head")
    yield engine
    asyncio.run(engine.dispose())


def test_records_survive_fresh_repository_instances(postgres_engine: AsyncEngine) -> None:
    start = datetime(2026, 7, 14, 9, tzinfo=UTC)
    user = NormalizedEntity(entity_type=EntityType.USER, username="jdoe", domain="CORP")
    first_event = NormalizedEvent(
        raw_event_id=uuid4(),
        source_system=SourceSystem.ACTIVE_DIRECTORY,
        event_type=NormalizedEventType.AUTH_FAILED,
        severity=Severity.MEDIUM,
        primary_entity=user,
        occurred_at=start,
    )
    second_event = NormalizedEvent(
        raw_event_id=uuid4(),
        source_system=SourceSystem.JUMPSERVER,
        event_type=NormalizedEventType.SESSION_STARTED,
        severity=Severity.HIGH,
        primary_entity=user,
        occurred_at=start + timedelta(minutes=2),
        extra_attributes={"remote_addr": "10.20.30.40"},
    )
    incident = Incident(
        title="Synthetic persistent incident",
        summary="Synthetic evidence retained across repository construction.",
        event_ids=[first_event.id, second_event.id],
        entities=[user],
        severity=Severity.HIGH,
        risk_score=62,
        created_at=start + timedelta(minutes=2),
        correlation_rule_id="synthetic_persistence_rule",
    )
    analysis = RootCauseAnalysis(
        probable_cause="Synthetic authentication activity preceded privileged access.",
        confidence=0.86,
        evidence=[Evidence(event_id=first_event.id, description="Synthetic failed login.")],
        recommended_actions=[],
        side_effects="An operator should verify expected administrative activity.",
    )
    action = ActionAuditRecord(
        action=RecommendedAction(
            action_type=ResponseActionType.DISABLE_USER,
            rationale="Suspend the synthetic account pending review.",
            requires_approval=True,
        ),
        incident_id=incident.id,
        approval_status=ApprovalStatus.PENDING,
    )

    event_store: EventStore = PostgresEventStore(postgres_engine)
    incident_store: IncidentStore = PostgresIncidentStore(postgres_engine)
    approval_store: ApprovalStore = PostgresApprovalStore(postgres_engine)
    event_store.add_all([first_event, second_event])
    assert incident_store.upsert(incident) is True
    incident_store.save_analysis(incident.id, analysis)
    approval_store.append(action)

    fresh_events: EventStore = PostgresEventStore(postgres_engine)
    fresh_incidents: IncidentStore = PostgresIncidentStore(postgres_engine)
    fresh_approvals: ApprovalStore = PostgresApprovalStore(postgres_engine)

    assert fresh_events.get_many([second_event.id, first_event.id]) == [
        second_event,
        first_event,
    ]
    assert {event.id for event in fresh_events.get_all()} >= {first_event.id, second_event.id}
    assert fresh_incidents.get(incident.id) == incident
    assert fresh_incidents.get_analysis(incident.id) == analysis
    assert fresh_approvals.get(action.id) == action
    assert fresh_approvals.history(action.id) == (action,)
    assert fresh_approvals.list_for_incident(incident.id) == [action]

    async def clean_up() -> None:
        async with postgres_engine.begin() as connection:
            await connection.execute(
                delete(ResponseActionAuditRecord).where(
                    ResponseActionAuditRecord.record_id == action.id
                )
            )
            await connection.execute(delete(IncidentRecord).where(IncidentRecord.id == incident.id))
            await connection.execute(
                delete(NormalizedEventRecord).where(
                    NormalizedEventRecord.id.in_([first_event.id, second_event.id])
                )
            )

    asyncio.run(clean_up())
