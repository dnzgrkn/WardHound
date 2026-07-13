from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from app.engines.pipeline import run_pipeline
from app.engines.policy import PolicyConfig
from app.schemas.events import (
    EntityType,
    NormalizedEntity,
    NormalizedEvent,
    NormalizedEventType,
    Severity,
    SourceSystem,
)


def test_pipeline_attaches_policy_and_risk() -> None:
    start = datetime(2026, 7, 13, 9, tzinfo=UTC)
    user = NormalizedEntity(entity_type=EntityType.USER, username="jdoe")
    events = [
        _event(
            SourceSystem.ACTIVE_DIRECTORY,
            NormalizedEventType.AUTH_FAILED,
            Severity.MEDIUM,
            user,
            start,
        ),
        _event(
            SourceSystem.PACKETFENCE,
            NormalizedEventType.DEVICE_QUARANTINED,
            Severity.HIGH,
            NormalizedEntity(entity_type=EntityType.DEVICE, mac_address="aa:bb:cc:dd:ee:ff"),
            start + timedelta(minutes=5),
            related=[user],
        ),
        _event(
            SourceSystem.JUMPSERVER,
            NormalizedEventType.SESSION_STARTED,
            Severity.MEDIUM,
            user,
            start + timedelta(minutes=10),
            related=[NormalizedEntity(entity_type=EntityType.DEVICE, hostname="SRV-T0-0042")],
            extra_attributes={"remote_addr": "10.20.30.40"},
        ),
    ]

    incidents = run_pipeline(
        events,
        PolicyConfig(
            tier_zero_assets=frozenset({"SRV-T0-0042"}),
            paw_devices=frozenset({"10.20.30.10"}),
        ),
    )

    assert incidents[0].policy_violations[0].rule_id == "tier_zero_from_non_paw"
    assert incidents[0].risk_score > 0
    assert incidents[0].severity is Severity.CRITICAL


def _event(
    source_system: SourceSystem,
    event_type: NormalizedEventType,
    severity: Severity,
    primary_entity: NormalizedEntity,
    occurred_at: datetime,
    *,
    related: list[NormalizedEntity] | None = None,
    extra_attributes: dict[str, str] | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        raw_event_id=uuid4(),
        source_system=source_system,
        event_type=event_type,
        severity=severity,
        primary_entity=primary_entity,
        related_entities=related or [],
        occurred_at=occurred_at,
        extra_attributes=extra_attributes or {},
    )
