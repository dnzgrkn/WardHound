"""Direct coverage for deterministic daily digest aggregation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from app.engines.digest import DigestBuilder, create_digest_narrative_engine_from_env
from app.engines.response import InMemoryApprovalStore
from app.schemas.analysis import RecommendedAction, ResponseActionType
from app.schemas.digest import AggregateStat
from app.schemas.events import (
    EntityType,
    NormalizedEntity,
    NormalizedEvent,
    NormalizedEventType,
    Severity,
    SourceSystem,
)
from app.schemas.incidents import Incident
from app.schemas.response import (
    ActionAuditRecord,
    ApprovalStatus,
    ExecutionStatus,
    SimulatedActionResult,
)
from app.stores.incidents import InMemoryEventStore, InMemoryIncidentStore


def _event(
    event_type: NormalizedEventType,
    occurred_at: datetime,
    entity: NormalizedEntity,
) -> NormalizedEvent:
    return NormalizedEvent(
        raw_event_id=uuid4(),
        source_system=SourceSystem.ACTIVE_DIRECTORY,
        event_type=event_type,
        severity=Severity.MEDIUM,
        primary_entity=entity,
        occurred_at=occurred_at,
    )


def _incident(created_at: datetime, severity: Severity, event_id: UUID) -> Incident:
    user = NormalizedEntity(entity_type=EntityType.USER, username="synthetic-operator")
    return Incident(
        title="Synthetic digest incident",
        summary="Synthetic activity used to verify digest aggregation.",
        event_ids=[event_id],
        entities=[user],
        severity=severity,
        risk_score=55,
        created_at=created_at,
        correlation_rule_id="synthetic_digest_rule",
    )


def _stat(
    stats: list[AggregateStat], name: str, label: str
) -> AggregateStat:
    return next(stat for stat in stats if stat.name == name and stat.label == label)


async def test_builder_filters_half_open_window_ranks_and_caps() -> None:
    start = datetime(2026, 7, 15, 12, tzinfo=UTC)
    end = start + timedelta(days=1)
    users = [
        NormalizedEntity(entity_type=EntityType.USER, username=f"synthetic-user-{index}")
        for index in range(3)
    ]
    device = NormalizedEntity(
        entity_type=EntityType.DEVICE,
        hostname="SYNTHETIC-DEVICE-0042",
    )
    events = [
        _event(NormalizedEventType.AUTH_FAILED, start, users[0]),
        _event(NormalizedEventType.AUTH_FAILED, start + timedelta(hours=1), users[0]),
        _event(NormalizedEventType.AUTH_FAILED, end - timedelta(microseconds=1), users[0]),
        _event(NormalizedEventType.AUTH_FAILED, start + timedelta(hours=2), users[1]),
        _event(NormalizedEventType.AUTH_FAILED, start + timedelta(hours=3), users[1]),
        _event(NormalizedEventType.AUTH_FAILED, start + timedelta(hours=4), users[2]),
        _event(NormalizedEventType.AUTH_FAILED, start - timedelta(microseconds=1), users[2]),
        _event(NormalizedEventType.AUTH_FAILED, end, users[2]),
        _event(NormalizedEventType.DEVICE_UNKNOWN, start + timedelta(hours=5), device),
        _event(
            NormalizedEventType.PRIVILEGED_COMMAND_EXECUTED,
            start + timedelta(hours=6),
            users[1],
        ),
    ]
    event_store = InMemoryEventStore()
    await event_store.add_all(events)
    incident_store = InMemoryIncidentStore()
    included = _incident(start, Severity.HIGH, events[0].id)
    excluded = _incident(end, Severity.CRITICAL, events[-1].id)
    await incident_store.upsert(included)
    await incident_store.upsert(excluded)

    digest = await DigestBuilder(
        event_store,
        incident_store,
        InMemoryApprovalStore(),
        ranking_limit=2,
    ).build(start, end)

    auth_stats = [
        stat for stat in digest.aggregate_stats if stat.name == "failed_authentication_by_user"
    ]
    assert [(stat.label, stat.count, stat.rank) for stat in auth_stats] == [
        ("synthetic-user-0", 3, 1),
        ("synthetic-user-1", 2, 2),
    ]
    assert _stat(
        digest.aggregate_stats, "device_security_activity", "SYNTHETIC-DEVICE-0042"
    ).count == 1
    assert _stat(
        digest.aggregate_stats, "privileged_activity_by_user", "synthetic-user-1"
    ).count == 1
    assert _stat(digest.aggregate_stats, "incidents_by_severity", "high").count == 1
    assert _stat(digest.aggregate_stats, "incidents_by_severity", "critical").count == 0
    assert digest.incidents == [included]
    assert digest.narrative is None


async def test_builder_summarizes_latest_response_actions() -> None:
    start = datetime(2026, 7, 15, 12, tzinfo=UTC)
    end = start + timedelta(days=1)
    user = NormalizedEntity(entity_type=EntityType.USER, username="synthetic-responder")
    event = _event(NormalizedEventType.AUTH_FAILED, start, user)
    event_store = InMemoryEventStore()
    await event_store.add_all([event])
    incident = _incident(start, Severity.MEDIUM, event.id)
    incident_store = InMemoryIncidentStore()
    await incident_store.upsert(incident)
    approvals = InMemoryApprovalStore()
    action = RecommendedAction(
        action_type=ResponseActionType.NOTIFY_ADMINISTRATOR,
        rationale="Notify an operator about synthetic digest activity.",
        requires_approval=False,
    )
    simulated = ActionAuditRecord(
        action=action,
        incident_id=incident.id,
        approval_status=ApprovalStatus.AUTO_APPROVED,
        execution_status=ExecutionStatus.SIMULATED,
        requested_at=start + timedelta(hours=1),
        result=SimulatedActionResult(
            description="Synthetic simulation completed.",
            details={"mode": "simulation"},
        ),
    )
    real = ActionAuditRecord(
        action=action,
        incident_id=incident.id,
        approval_status=ApprovalStatus.APPROVED,
        decided_by="synthetic-approver",
        decided_at=start + timedelta(hours=2),
        execution_status=ExecutionStatus.SIMULATED,
        requested_at=start - timedelta(days=1),
        result=SimulatedActionResult(
            description="Synthetic real-mode execution completed.",
            details={"mode": "real"},
        ),
    )
    rejected = ActionAuditRecord(
        action=action,
        incident_id=incident.id,
        approval_status=ApprovalStatus.REJECTED,
        decided_by="synthetic-approver",
        decided_at=start + timedelta(hours=3),
        requested_at=start + timedelta(hours=1),
        reason="Synthetic rejection.",
    )
    for record in (simulated, real, rejected):
        await approvals.append(record)

    digest = await DigestBuilder(event_store, incident_store, approvals).build(start, end)

    assert _stat(digest.aggregate_stats, "response_approval", "approved").count == 2
    assert _stat(digest.aggregate_stats, "response_approval", "rejected").count == 1
    assert _stat(digest.aggregate_stats, "response_execution", "real").count == 1
    assert _stat(digest.aggregate_stats, "response_execution", "simulated").count == 1


async def test_missing_anthropic_key_degrades_to_deterministic_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    start = datetime(2026, 7, 15, 12, tzinfo=UTC)
    user = NormalizedEntity(entity_type=EntityType.USER, username="synthetic-no-ai-user")
    event = _event(NormalizedEventType.AUTH_FAILED, start, user)
    event_store = InMemoryEventStore()
    await event_store.add_all([event])

    digest = await DigestBuilder(
        event_store,
        InMemoryIncidentStore(),
        InMemoryApprovalStore(),
        create_digest_narrative_engine_from_env,
    ).build(start, start + timedelta(days=1))

    assert digest.narrative is None
    assert _stat(
        digest.aggregate_stats,
        "failed_authentication_by_user",
        "synthetic-no-ai-user",
    ).count == 1
