from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from app.engines.correlation import CorrelationEngine, CrossSystemCompromiseRule
from app.schemas.events import (
    EntityType,
    NormalizedEntity,
    NormalizedEvent,
    NormalizedEventType,
    Severity,
    SourceSystem,
)


def make_event(
    source: SourceSystem,
    event_type: NormalizedEventType,
    occurred_at: datetime,
    *,
    username: str | None = None,
    mac_address: str | None = None,
    related: list[NormalizedEntity] | None = None,
    extra_attributes: dict[str, str] | None = None,
) -> NormalizedEvent:
    entity_type = EntityType.USER if username else EntityType.DEVICE
    return NormalizedEvent(
        raw_event_id=uuid4(),
        source_system=source,
        event_type=event_type,
        severity=(
            Severity.HIGH
            if event_type is NormalizedEventType.DEVICE_QUARANTINED
            else Severity.MEDIUM
        ),
        primary_entity=NormalizedEntity(
            entity_type=entity_type,
            username=username,
            mac_address=mac_address,
        ),
        related_entities=related or [],
        occurred_at=occurred_at,
        extra_attributes=extra_attributes or {},
    )


def correlated_events(*, jump_offset: timedelta = timedelta(minutes=10)) -> list[NormalizedEvent]:
    start = datetime(2026, 7, 13, 9, tzinfo=UTC)
    user = NormalizedEntity(entity_type=EntityType.USER, username="jdoe", domain="CORP")
    target = NormalizedEntity(entity_type=EntityType.DEVICE, hostname="SRV-T0-0042")
    return [
        make_event(
            SourceSystem.ACTIVE_DIRECTORY,
            NormalizedEventType.AUTH_FAILED,
            start,
            username="jdoe",
        ),
        make_event(
            SourceSystem.PACKETFENCE,
            NormalizedEventType.DEVICE_QUARANTINED,
            start + timedelta(minutes=5),
            mac_address="aa:bb:cc:dd:ee:ff",
            related=[user],
        ),
        make_event(
            SourceSystem.JUMPSERVER,
            NormalizedEventType.SESSION_STARTED,
            start + jump_offset,
            username="JDOE",
            related=[target],
            extra_attributes={"remote_addr": "10.20.30.40"},
        ),
    ]


def test_correlates_same_username_inside_window() -> None:
    incidents = CorrelationEngine().correlate(correlated_events())

    assert len(incidents) == 1
    assert incidents[0].correlation_rule_id == "cross_system_auth_quarantine_session"
    assert len(incidents[0].event_ids) == 3
    assert incidents[0].severity is Severity.HIGH


def test_does_not_correlate_events_outside_window() -> None:
    incidents = CorrelationEngine().correlate(correlated_events(jump_offset=timedelta(minutes=16)))

    assert incidents == []


def test_window_boundary_is_inclusive() -> None:
    incidents = CorrelationEngine().correlate(
        correlated_events(jump_offset=timedelta(minutes=15))
    )

    assert len(incidents) == 1


def test_rejects_non_positive_window() -> None:
    engine = CorrelationEngine(rules=[CrossSystemCompromiseRule(window=timedelta(0))])

    with pytest.raises(ValueError, match="must be positive"):
        engine.correlate(correlated_events())


def test_uses_mac_as_secondary_entity_key() -> None:
    start = datetime(2026, 7, 13, 9, tzinfo=UTC)
    events = [
        make_event(
            SourceSystem.ACTIVE_DIRECTORY,
            NormalizedEventType.AUTH_FAILED,
            start,
            mac_address="aa:bb:cc:dd:ee:ff",
        ),
        make_event(
            SourceSystem.PACKETFENCE,
            NormalizedEventType.DEVICE_QUARANTINED,
            start + timedelta(minutes=1),
            mac_address="AA:BB:CC:DD:EE:FF",
        ),
        make_event(
            SourceSystem.JUMPSERVER,
            NormalizedEventType.SESSION_STARTED,
            start + timedelta(minutes=2),
            mac_address="aa:bb:cc:dd:ee:ff",
        ),
    ]

    incidents = CorrelationEngine().correlate(events)

    assert len(incidents) == 1


def test_does_not_use_mac_to_override_conflicting_usernames() -> None:
    start = datetime(2026, 7, 13, 9, tzinfo=UTC)
    events = [
        make_event(
            SourceSystem.ACTIVE_DIRECTORY,
            NormalizedEventType.AUTH_FAILED,
            start,
            username="jdoe",
            related=[
                NormalizedEntity(entity_type=EntityType.DEVICE, mac_address="aa:bb:cc:dd:ee:ff")
            ],
        ),
        make_event(
            SourceSystem.PACKETFENCE,
            NormalizedEventType.DEVICE_QUARANTINED,
            start + timedelta(minutes=1),
            mac_address="aa:bb:cc:dd:ee:ff",
            related=[NormalizedEntity(entity_type=EntityType.USER, username="asmith")],
        ),
        make_event(
            SourceSystem.JUMPSERVER,
            NormalizedEventType.SESSION_STARTED,
            start + timedelta(minutes=2),
            username="jdoe",
            related=[
                NormalizedEntity(entity_type=EntityType.DEVICE, mac_address="aa:bb:cc:dd:ee:ff")
            ],
        ),
    ]

    assert CorrelationEngine().correlate(events) == []


def test_clusters_repeated_evidence_for_entity_inside_window() -> None:
    first_chain = correlated_events()
    second_chain = correlated_events()
    events = [
        event.model_copy(update={"occurred_at": event.occurred_at + timedelta(minutes=1)})
        for event in second_chain
    ]
    events.extend(first_chain)

    incidents = CorrelationEngine().correlate(events)

    assert len(incidents) == 1
    assert set(incidents[0].event_ids) == {event.id for event in events}
    assert len(incidents[0].event_ids) == 6


def test_reports_time_separated_clusters_for_same_entity() -> None:
    first_chain = correlated_events()
    second_chain = [
        event.model_copy(update={"occurred_at": event.occurred_at + timedelta(hours=2)})
        for event in correlated_events()
    ]

    incidents = CorrelationEngine().correlate([*second_chain, *first_chain])

    assert len(incidents) == 2
    assert {frozenset(incident.event_ids) for incident in incidents} == {
        frozenset(event.id for event in first_chain),
        frozenset(event.id for event in second_chain),
    }
    assert incidents[0].id != incidents[1].id


def test_rule_registry_accepts_configured_window() -> None:
    engine = CorrelationEngine(rules=[CrossSystemCompromiseRule(window=timedelta(minutes=5))])

    assert engine.correlate(correlated_events()) == []
