"""Thin composition of the independent Stage 3 engines."""

from __future__ import annotations

from collections.abc import Iterable

from app.engines.correlation import CorrelationEngine
from app.engines.policy import PolicyConfig, PolicyEngine
from app.engines.risk import RiskEngine
from app.schemas.events import NormalizedEvent
from app.schemas.incidents import Incident


def run_pipeline(
    events: Iterable[NormalizedEvent], policy_config: PolicyConfig | None = None
) -> list[Incident]:
    """Correlate events, evaluate incident evidence, and attach deterministic risk."""
    event_list = tuple(events)
    event_by_id = {event.id: event for event in event_list}
    incidents = CorrelationEngine().correlate(event_list)
    policy_engine = PolicyEngine(policy_config or PolicyConfig())
    risk_engine = RiskEngine()
    enriched: list[Incident] = []
    for incident in incidents:
        evidence = [event_by_id[event_id] for event_id in incident.event_ids]
        violations = policy_engine.evaluate(evidence)
        assessment = risk_engine.score(evidence, violations)
        enriched.append(
            incident.model_copy(
                update={
                    "policy_violations": violations,
                    "risk_score": assessment.score,
                    "severity": assessment.severity,
                }
            )
        )
    return enriched
