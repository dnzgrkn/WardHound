from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from app.engines.response import (
    InMemoryApprovalStore,
    ResponseEngine,
    action_context_from_incident,
)
from app.schemas.analysis import RecommendedAction, ResponseActionType
from app.schemas.events import (
    EntityType,
    NormalizedEntity,
    NormalizedEvent,
    NormalizedEventType,
    Severity,
    SourceSystem,
)
from app.schemas.incidents import Incident
from app.schemas.response import ApprovalStatus, ExecutionStatus


def incident_and_evidence() -> tuple[Incident, NormalizedEvent]:
    entities = [
        NormalizedEntity(
            entity_type=EntityType.DEVICE,
            hostname="WKSTN-0042",
            mac_address="aa:bb:cc:dd:ee:ff",
        ),
        NormalizedEntity(
            entity_type=EntityType.USER,
            username="jdoe",
            domain="CORP",
        ),
        NormalizedEntity(
            entity_type=EntityType.IP_ADDRESS,
            ip_address="10.20.30.40",
        ),
    ]
    event = NormalizedEvent(
        raw_event_id=uuid4(),
        source_system=SourceSystem.JUMPSERVER,
        event_type=NormalizedEventType.SESSION_ANOMALY_DETECTED,
        severity=Severity.HIGH,
        primary_entity=entities[1],
        related_entities=[entities[0], entities[2]],
        occurred_at=datetime(2026, 7, 13, 10, tzinfo=UTC),
        extra_attributes={"session_id": "session-synthetic-0042"},
    )
    incident = Incident(
        title="Synthetic privileged session anomaly",
        summary="A synthetic session crossed an expected access boundary.",
        event_ids=[event.id],
        entities=entities,
        severity=Severity.HIGH,
        risk_score=74,
        correlation_rule_id="synthetic_session_rule",
        created_at=event.occurred_at,
    )
    return incident, event


def action(action_type: ResponseActionType, requires_approval: bool) -> RecommendedAction:
    return RecommendedAction(
        action_type=action_type,
        rationale="Synthetic response recommendation for an audit test.",
        requires_approval=requires_approval,
    )


def test_privileged_action_waits_for_approval_before_simulation() -> None:
    incident, event = incident_and_evidence()
    store = InMemoryApprovalStore()
    engine = ResponseEngine(store)
    requested = engine.request_action(
        action(ResponseActionType.QUARANTINE_DEVICE, requires_approval=True),
        incident.id,
        action_context_from_incident(incident, [event]),
    )

    assert requested.approval_status is ApprovalStatus.PENDING
    assert requested.execution_status is ExecutionStatus.NOT_EXECUTED
    assert requested.result is None

    approved = engine.approve(requested.id, decided_by="analyst-01")

    assert approved.approval_status is ApprovalStatus.APPROVED
    assert approved.execution_status is ExecutionStatus.SIMULATED
    assert approved.result is not None
    assert "AA:BB:CC:DD:EE:FF" in approved.result.description
    assert requested.execution_status is ExecutionStatus.NOT_EXECUTED
    assert [snapshot.execution_status for snapshot in store.history(requested.id)] == [
        ExecutionStatus.NOT_EXECUTED,
        ExecutionStatus.NOT_EXECUTED,
        ExecutionStatus.SIMULATED,
    ]


def test_non_privileged_action_is_auto_approved_and_simulated() -> None:
    incident, event = incident_and_evidence()
    engine = ResponseEngine(InMemoryApprovalStore())

    record = engine.request_action(
        action(ResponseActionType.NOTIFY_ADMINISTRATOR, requires_approval=False),
        incident.id,
        action_context_from_incident(incident, [event]),
    )

    assert record.approval_status is ApprovalStatus.AUTO_APPROVED
    assert record.execution_status is ExecutionStatus.SIMULATED
    assert record.result is not None
    assert record.result.details["mode"] == "simulation"


def test_rejection_never_executes_handler() -> None:
    store = InMemoryApprovalStore()
    engine = ResponseEngine(store)
    requested = engine.request_action(
        action(ResponseActionType.DISABLE_USER, requires_approval=True)
    )

    rejected = engine.reject(
        requested.id,
        decided_by="analyst-01",
        reason="The synthetic activity was expected.",
    )

    assert rejected.approval_status is ApprovalStatus.REJECTED
    assert rejected.execution_status is ExecutionStatus.NOT_EXECUTED
    assert rejected.result is None
    assert rejected.reason == "The synthetic activity was expected."
    assert len(store.history(requested.id)) == 2


def test_engine_defensively_gates_constructed_privileged_bypass() -> None:
    bypass = RecommendedAction.model_construct(
        action_type=ResponseActionType.BLOCK_IP,
        rationale="Attempt to bypass schema validation in a synthetic test.",
        requires_approval=False,
    )
    engine = ResponseEngine(InMemoryApprovalStore())

    record = engine.request_action(bypass)

    assert record.approval_status is ApprovalStatus.PENDING
    assert record.execution_status is ExecutionStatus.NOT_EXECUTED
    assert record.result is None
    assert record.action.requires_approval is True


@pytest.mark.parametrize(
    ("action_type", "expected_text"),
    [
        (ResponseActionType.QUARANTINE_DEVICE, "PacketFence"),
        (ResponseActionType.DISABLE_USER, "CORP\\jdoe"),
        (ResponseActionType.BLOCK_IP, "10.20.30.40"),
        (ResponseActionType.CLOSE_SESSION, "session-synthetic-0042"),
        (ResponseActionType.REQUIRE_MFA, "MFA challenge"),
        (ResponseActionType.NOTIFY_ADMINISTRATOR, "administrator notification"),
        (ResponseActionType.CREATE_INCIDENT, "incident tracking record"),
        (ResponseActionType.REQUIRE_MANUAL_APPROVAL, "manual-approval checkpoint"),
    ],
)
def test_every_action_type_has_a_sane_simulated_handler(
    action_type: ResponseActionType, expected_text: str
) -> None:
    incident, event = incident_and_evidence()
    engine = ResponseEngine(InMemoryApprovalStore())
    requires_approval = action_type in RecommendedAction.PRIVILEGED_ACTIONS
    record = engine.request_action(
        action(action_type, requires_approval=requires_approval),
        incident.id,
        action_context_from_incident(incident, [event]),
    )
    if record.approval_status is ApprovalStatus.PENDING:
        record = engine.approve(record.id, decided_by="analyst-01")

    assert record.execution_status is ExecutionStatus.SIMULATED
    assert record.result is not None
    assert expected_text in record.result.description
    assert record.result.details["mode"] == "simulation"


def test_malformed_target_is_a_failed_simulation() -> None:
    engine = ResponseEngine(InMemoryApprovalStore())
    requested = engine.request_action(
        action(ResponseActionType.QUARANTINE_DEVICE, requires_approval=True)
    )

    record = engine.approve(requested.id, decided_by="analyst-01")

    assert record.execution_status is ExecutionStatus.FAILED
    assert record.result is not None
    assert "device MAC address is missing" in record.result.description
