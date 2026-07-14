from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from app.engines.risk import RiskConfig, RiskEngine
from app.schemas.events import (
    EntityType,
    NormalizedEntity,
    NormalizedEvent,
    NormalizedEventType,
    Severity,
    SourceSystem,
)
from app.schemas.incidents import PolicyViolation


def make_event(event_type: NormalizedEventType, severity: Severity) -> NormalizedEvent:
    return NormalizedEvent(
        raw_event_id=uuid4(),
        source_system=SourceSystem.PACKETFENCE,
        event_type=event_type,
        severity=severity,
        primary_entity=NormalizedEntity(
            entity_type=EntityType.DEVICE,
            mac_address="aa:bb:cc:dd:ee:ff",
        ),
        occurred_at=datetime(2026, 7, 13, 9, tzinfo=UTC),
    )


def test_score_increases_with_event_severity_and_correlation() -> None:
    engine = RiskEngine()
    low = engine.score([make_event(NormalizedEventType.AUTH_SUCCEEDED, Severity.LOW)])
    high = engine.score(
        [
            make_event(NormalizedEventType.AUTH_FAILED, Severity.HIGH),
            make_event(NormalizedEventType.DEVICE_QUARANTINED, Severity.HIGH),
        ]
    )

    assert low.score == 4
    assert low.severity is Severity.LOW
    assert high.score == 60
    assert high.severity is Severity.HIGH


def test_policy_violation_adds_bonus_and_changes_band() -> None:
    event = make_event(NormalizedEventType.DEVICE_QUARANTINED, Severity.HIGH)
    violation = PolicyViolation(
        rule_id="synthetic_policy",
        title="Synthetic policy violation",
        description="Synthetic evidence used to verify deterministic scoring.",
        event_ids=[event.id],
        entities=[event.primary_entity],
        severity=Severity.HIGH,
    )
    without_violation = RiskEngine().score([event])
    with_violation = RiskEngine().score([event], [violation])

    assert without_violation.score == 36
    assert without_violation.severity is Severity.MEDIUM
    assert with_violation.score == 51
    assert with_violation.severity is Severity.HIGH


def test_rejects_empty_evidence() -> None:
    with pytest.raises(ValueError, match="at least one event"):
        RiskEngine().score([])


@pytest.mark.parametrize(
    ("event_weight", "severity_weight", "expected"),
    [(200, 0, 100), (-200, 0, 0)],
)
def test_score_is_capped_at_both_bounds(
    event_weight: int, severity_weight: int, expected: int
) -> None:
    event = make_event(NormalizedEventType.AUTH_SUCCEEDED, Severity.LOW)
    config = RiskConfig(
        event_weights={NormalizedEventType.AUTH_SUCCEEDED: event_weight},
        severity_weights={Severity.LOW: severity_weight},
    )

    assessment = RiskEngine(config).score([event])

    assert assessment.score == expected
