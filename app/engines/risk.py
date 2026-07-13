"""Deterministic weighted incident risk scoring."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from pydantic import BaseModel, Field

from app.schemas.events import NormalizedEvent, NormalizedEventType, Severity
from app.schemas.incidents import PolicyViolation

DEFAULT_EVENT_WEIGHTS: dict[NormalizedEventType, int] = {
    NormalizedEventType.AUTH_FAILED: 8,
    NormalizedEventType.AUTH_SUCCEEDED: 2,
    NormalizedEventType.ACCOUNT_LOCKED_OUT: 20,
    NormalizedEventType.DEVICE_UNKNOWN: 8,
    NormalizedEventType.DEVICE_REGISTERED: 2,
    NormalizedEventType.DEVICE_QUARANTINED: 24,
    NormalizedEventType.VLAN_ASSIGNED: 5,
    NormalizedEventType.SESSION_STARTED: 12,
    NormalizedEventType.SESSION_ENDED: 3,
    NormalizedEventType.PRIVILEGED_COMMAND_EXECUTED: 15,
    NormalizedEventType.SESSION_ANOMALY_DETECTED: 25,
    NormalizedEventType.PASSWORD_SPRAY_DETECTED: 24,
    NormalizedEventType.GROUP_MEMBERSHIP_CHANGED: 18,
    NormalizedEventType.TIER_VIOLATION_DETECTED: 25,
    NormalizedEventType.TRAFFIC_BLOCKED: 8,
    NormalizedEventType.LATERAL_MOVEMENT_ATTEMPT: 25,
    NormalizedEventType.PORT_SCAN_DETECTED: 18,
    NormalizedEventType.UNEXPECTED_EAST_WEST_TRAFFIC: 20,
}

DEFAULT_SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.LOW: 2,
    Severity.MEDIUM: 6,
    Severity.HIGH: 12,
    Severity.CRITICAL: 20,
}


class RiskAssessment(BaseModel):
    """Bounded score and corresponding operator-facing risk band."""

    model_config = {"frozen": True}

    score: float = Field(ge=0, le=100)
    severity: Severity


@dataclass(frozen=True)
class RiskConfig:
    """Readable scoring weights that can be replaced without changing engine logic."""

    event_weights: Mapping[NormalizedEventType, int] = field(
        default_factory=lambda: dict(DEFAULT_EVENT_WEIGHTS)
    )
    severity_weights: Mapping[Severity, int] = field(
        default_factory=lambda: dict(DEFAULT_SEVERITY_WEIGHTS)
    )
    correlated_event_bonus: int = 4
    policy_violation_bonus: int = 15


class RiskEngine:
    """Score incident evidence using deterministic additive weights."""

    def __init__(self, config: RiskConfig | None = None) -> None:
        self.config = config or RiskConfig()

    def score(
        self,
        events: Iterable[NormalizedEvent],
        policy_violations: Iterable[PolicyViolation] = (),
    ) -> RiskAssessment:
        """Calculate a capped 0-100 score and its stable severity band."""
        event_list = tuple(events)
        if not event_list:
            raise ValueError("Risk scoring requires at least one event")
        missing_types = {
            event.event_type
            for event in event_list
            if event.event_type not in self.config.event_weights
        }
        if missing_types:
            names = ", ".join(sorted(event_type.value for event_type in missing_types))
            raise ValueError(f"Risk weights missing event types: {names}")
        base = sum(
            self.config.event_weights[event.event_type]
            + self.config.severity_weights[event.severity]
            for event in event_list
        )
        correlation_bonus = max(0, len(event_list) - 1) * self.config.correlated_event_bonus
        violation_bonus = self.config.policy_violation_bonus if any(policy_violations) else 0
        score = float(min(100, max(0, base + correlation_bonus + violation_bonus)))
        return RiskAssessment(score=score, severity=_risk_band(score))


def _risk_band(score: float) -> Severity:
    if score >= 75:
        return Severity.CRITICAL
    if score >= 50:
        return Severity.HIGH
    if score >= 25:
        return Severity.MEDIUM
    return Severity.LOW
