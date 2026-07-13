from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from app.engines.analysis import (
    AIAnalysisEngine,
    AnalysisConfigurationError,
    AnalysisGenerationError,
    AnalysisMessage,
    create_analysis_engine_from_env,
)
from app.schemas.analysis import (
    Evidence,
    RecommendedAction,
    ResponseActionType,
    RootCauseAnalysis,
)
from app.schemas.events import (
    EntityType,
    NormalizedEntity,
    NormalizedEvent,
    NormalizedEventType,
    Severity,
    SourceSystem,
)
from app.schemas.incidents import Incident


def valid_analysis(event_id: UUID) -> RootCauseAnalysis:
    return RootCauseAnalysis(
        probable_cause="A synthetic identity failure preceded NAC containment.",
        confidence=0.82,
        evidence=[
            Evidence(
                event_id=event_id,
                description="PacketFence isolated the synthetic endpoint.",
            )
        ],
        recommended_actions=[
            RecommendedAction(
                action_type=ResponseActionType.NOTIFY_ADMINISTRATOR,
                rationale="An operator should verify whether the access was expected.",
                requires_approval=False,
            )
        ],
        side_effects="Notification may create duplicate investigation work.",
    )


class StubAnalysisClient:
    def __init__(self, result: RootCauseAnalysis) -> None:
        self.result = result
        self.model: str | None = None
        self.max_tokens: int | None = None
        self.system: str | None = None
        self.messages: list[AnalysisMessage] = []

    async def create_analysis(
        self,
        *,
        model: str,
        max_tokens: int,
        system: str,
        messages: list[AnalysisMessage],
        max_retries: int,
    ) -> RootCauseAnalysis:
        self.model = model
        self.max_tokens = max_tokens
        self.system = system
        self.messages = messages
        assert max_retries == 2
        return self.result


class FailingAnalysisClient:
    async def create_analysis(
        self,
        *,
        model: str,
        max_tokens: int,
        system: str,
        messages: list[AnalysisMessage],
        max_retries: int,
    ) -> RootCauseAnalysis:
        raise RuntimeError("synthetic Instructor retry exhaustion")


def incident_and_event() -> tuple[Incident, NormalizedEvent]:
    event = NormalizedEvent(
        raw_event_id=uuid4(),
        source_system=SourceSystem.PACKETFENCE,
        event_type=NormalizedEventType.DEVICE_QUARANTINED,
        severity=Severity.HIGH,
        primary_entity=NormalizedEntity(
            entity_type=EntityType.DEVICE,
            mac_address="aa:bb:cc:dd:ee:ff",
            hostname="WKSTN-0042",
        ),
        related_entities=[
            NormalizedEntity(entity_type=EntityType.USER, username="jdoe", domain="CORP")
        ],
        occurred_at=datetime(2026, 7, 13, 9, tzinfo=UTC),
        extra_attributes={"category": "Isolation", "status": "reg"},
    )
    incident = Incident(
        title="Synthetic NAC containment",
        summary="A synthetic endpoint was isolated after authentication failures.",
        event_ids=[event.id],
        entities=[event.primary_entity, *event.related_entities],
        severity=Severity.HIGH,
        risk_score=72,
        created_at=event.occurred_at,
        correlation_rule_id="synthetic_nac_rule",
    )
    return incident, event


async def test_analyze_returns_structured_result_without_network() -> None:
    incident, event = incident_and_event()
    client = StubAnalysisClient(valid_analysis(event.id))
    engine = AIAnalysisEngine(client, model="synthetic-model", max_tokens=1024)

    result = await engine.analyze(incident, [event])

    assert result.confidence == 0.82
    assert result.evidence[0].event_id == event.id
    assert client.model == "synthetic-model"
    assert client.max_tokens == 1024
    assert client.system is not None
    assert "PacketFence NAC isolation" in client.system
    assert "JumpServer privileged-session" in client.system
    assert "Active Directory account lockout" in client.system
    assert str(event.id) in client.messages[0]["content"]
    assert "WKSTN-0042" in client.messages[0]["content"]


async def test_wraps_instructor_retry_exhaustion() -> None:
    incident, event = incident_and_event()
    engine = AIAnalysisEngine(FailingAnalysisClient())

    with pytest.raises(AnalysisGenerationError, match="structured validation failed"):
        await engine.analyze(incident, [event])


async def test_rejects_citation_outside_supplied_evidence() -> None:
    incident, event = incident_and_event()
    engine = AIAnalysisEngine(StubAnalysisClient(valid_analysis(uuid4())))

    with pytest.raises(AnalysisGenerationError, match="outside the supplied events"):
        await engine.analyze(incident, [event])


def test_real_client_factory_requires_api_key_only_when_called(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    with pytest.raises(AnalysisConfigurationError, match="ANTHROPIC_API_KEY"):
        create_analysis_engine_from_env()


@pytest.mark.parametrize("confidence", [-0.01, 1.01])
def test_analysis_rejects_confidence_outside_bounds(confidence: float) -> None:
    with pytest.raises(ValidationError):
        RootCauseAnalysis(
            probable_cause="Synthetic cause",
            confidence=confidence,
            evidence=[Evidence(event_id=uuid4(), description="Synthetic evidence")],
            recommended_actions=[],
            side_effects="Synthetic side effect",
        )


def test_analysis_requires_cited_evidence() -> None:
    with pytest.raises(ValidationError):
        RootCauseAnalysis(
            probable_cause="Synthetic cause",
            confidence=0.5,
            evidence=[],
            recommended_actions=[],
            side_effects="Synthetic side effect",
        )


def test_privileged_action_cannot_bypass_approval() -> None:
    with pytest.raises(ValidationError, match="must require approval"):
        RecommendedAction(
            action_type=ResponseActionType.DISABLE_USER,
            rationale="Synthetic containment recommendation",
            requires_approval=False,
        )
