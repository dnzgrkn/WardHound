from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from app.engines.policy import PolicyConfig, PolicyEngine
from app.schemas.events import (
    EntityType,
    NormalizedEntity,
    NormalizedEvent,
    NormalizedEventType,
    Severity,
    SourceSystem,
)


def test_flags_tier_zero_access_from_non_paw() -> None:
    event = NormalizedEvent(
        raw_event_id=uuid4(),
        source_system=SourceSystem.JUMPSERVER,
        event_type=NormalizedEventType.SESSION_STARTED,
        severity=Severity.LOW,
        primary_entity=NormalizedEntity(entity_type=EntityType.USER, username="jdoe"),
        related_entities=[NormalizedEntity(entity_type=EntityType.DEVICE, hostname="SRV-T0-0042")],
        occurred_at=datetime(2026, 7, 13, 9, tzinfo=UTC),
        extra_attributes={"remote_addr": "10.20.30.40"},
    )
    engine = PolicyEngine(
        PolicyConfig(
            tier_zero_assets=frozenset({"srv-t0-0042"}),
            paw_devices=frozenset({"10.20.30.10"}),
        )
    )

    violations = engine.evaluate([event])

    assert len(violations) == 1
    assert violations[0].rule_id == "tier_zero_from_non_paw"
    assert violations[0].event_ids == [event.id]


def test_allows_tier_zero_access_from_known_paw() -> None:
    event = NormalizedEvent(
        raw_event_id=uuid4(),
        source_system=SourceSystem.JUMPSERVER,
        event_type=NormalizedEventType.SESSION_STARTED,
        severity=Severity.LOW,
        primary_entity=NormalizedEntity(entity_type=EntityType.USER, username="jdoe"),
        related_entities=[NormalizedEntity(entity_type=EntityType.DEVICE, hostname="SRV-T0-0042")],
        occurred_at=datetime(2026, 7, 13, 9, tzinfo=UTC),
        extra_attributes={"source_device": "PAW-0042"},
    )
    engine = PolicyEngine(
        PolicyConfig(
            tier_zero_assets=frozenset({"SRV-T0-0042"}),
            paw_devices=frozenset({"paw-0042"}),
        )
    )

    assert engine.evaluate([event]) == []


def test_flags_access_by_configured_isolated_device() -> None:
    event = NormalizedEvent(
        raw_event_id=uuid4(),
        source_system=SourceSystem.PACKETFENCE,
        event_type=NormalizedEventType.AUTH_SUCCEEDED,
        severity=Severity.LOW,
        primary_entity=NormalizedEntity(
            entity_type=EntityType.DEVICE,
            mac_address="aa:bb:cc:dd:ee:ff",
        ),
        occurred_at=datetime(2026, 7, 13, 9, tzinfo=UTC),
    )
    engine = PolicyEngine(PolicyConfig(isolated_devices=frozenset({"AA:BB:CC:DD:EE:FF"})))

    violations = engine.evaluate([event])

    assert len(violations) == 1
    assert violations[0].rule_id == "quarantine_bypass_attempt"


def test_independent_rules_can_flag_same_batch() -> None:
    occurred_at = datetime(2026, 7, 13, 9, tzinfo=UTC)
    tier_zero_session = NormalizedEvent(
        raw_event_id=uuid4(),
        source_system=SourceSystem.JUMPSERVER,
        event_type=NormalizedEventType.SESSION_STARTED,
        severity=Severity.MEDIUM,
        primary_entity=NormalizedEntity(entity_type=EntityType.USER, username="jdoe"),
        related_entities=[
            NormalizedEntity(entity_type=EntityType.DEVICE, hostname="SRV-T0-0042")
        ],
        occurred_at=occurred_at,
        extra_attributes={"remote_addr": "10.20.30.40"},
    )
    isolated_access = NormalizedEvent(
        raw_event_id=uuid4(),
        source_system=SourceSystem.PACKETFENCE,
        event_type=NormalizedEventType.VLAN_ASSIGNED,
        severity=Severity.LOW,
        primary_entity=NormalizedEntity(
            entity_type=EntityType.DEVICE, mac_address="aa:bb:cc:dd:ee:ff"
        ),
        occurred_at=occurred_at,
    )
    engine = PolicyEngine(
        PolicyConfig(
            tier_zero_assets=frozenset({"srv-t0-0042"}),
            paw_devices=frozenset({"10.20.30.10"}),
            isolated_devices=frozenset({"AA:BB:CC:DD:EE:FF"}),
        )
    )

    violations = engine.evaluate([tier_zero_session, isolated_access])

    assert {violation.rule_id for violation in violations} == {
        "tier_zero_from_non_paw",
        "quarantine_bypass_attempt",
    }
