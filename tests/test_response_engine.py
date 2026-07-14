from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

import app.engines.response as response_module
from app.engines.response import (
    InMemoryApprovalStore,
    QuarantineDeviceHandler,
    ResponseEngine,
    action_context_from_incident,
)
from app.integrations.packetfence import PacketFenceError, PacketFenceIsolationResult
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


class StubPacketFenceClient:
    calls: list[str] = []
    error: PacketFenceError | None = None

    def __init__(self, base_url: str, api_token: str) -> None:
        assert base_url == "https://10.20.30.40:9999"
        assert api_token == "synthetic-api-token"

    async def __aenter__(self) -> StubPacketFenceClient:
        return self

    async def __aexit__(self, *args: object) -> None:
        return None

    async def isolate_node(self, mac_address: str) -> PacketFenceIsolationResult:
        self.calls.append(mac_address)
        if self.error is not None:
            raise self.error
        return PacketFenceIsolationResult(status_code=200, node_status="unreg")


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
        # Matches JumpServerCollector._normalize_command's real extra_attributes key
        # ("session"), not a "session_id" key — the response engine's session lookup
        # must agree with what the Stage 2 collector actually produces.
        extra_attributes={"session": "session-synthetic-0042"},
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


async def test_privileged_action_waits_for_approval_before_simulation() -> None:
    incident, event = incident_and_evidence()
    store = InMemoryApprovalStore()
    engine = ResponseEngine(store)
    requested = await engine.request_action(
        action(ResponseActionType.QUARANTINE_DEVICE, requires_approval=True),
        incident.id,
        action_context_from_incident(incident, [event]),
    )

    assert requested.approval_status is ApprovalStatus.PENDING
    assert requested.execution_status is ExecutionStatus.NOT_EXECUTED
    assert requested.result is None

    approved = await engine.approve(requested.id, decided_by="analyst-01")

    assert approved.approval_status is ApprovalStatus.APPROVED
    assert approved.execution_status is ExecutionStatus.SIMULATED
    assert approved.result is not None
    assert "AA:BB:CC:DD:EE:FF" in approved.result.description
    assert requested.execution_status is ExecutionStatus.NOT_EXECUTED
    assert [snapshot.execution_status for snapshot in await store.history(requested.id)] == [
        ExecutionStatus.NOT_EXECUTED,
        ExecutionStatus.NOT_EXECUTED,
        ExecutionStatus.SIMULATED,
    ]


async def test_non_privileged_action_is_auto_approved_and_simulated() -> None:
    incident, event = incident_and_evidence()
    engine = ResponseEngine(InMemoryApprovalStore())

    record = await engine.request_action(
        action(ResponseActionType.NOTIFY_ADMINISTRATOR, requires_approval=False),
        incident.id,
        action_context_from_incident(incident, [event]),
    )

    assert record.approval_status is ApprovalStatus.AUTO_APPROVED
    assert record.execution_status is ExecutionStatus.SIMULATED
    assert record.result is not None
    assert record.result.details["mode"] == "simulation"


async def test_rejection_never_executes_handler() -> None:
    store = InMemoryApprovalStore()
    engine = ResponseEngine(store)
    requested = await engine.request_action(
        action(ResponseActionType.DISABLE_USER, requires_approval=True)
    )

    rejected = await engine.reject(
        requested.id,
        decided_by="analyst-01",
        reason="The synthetic activity was expected.",
    )

    assert rejected.approval_status is ApprovalStatus.REJECTED
    assert rejected.execution_status is ExecutionStatus.NOT_EXECUTED
    assert rejected.result is None
    assert rejected.reason == "The synthetic activity was expected."
    assert len(await store.history(requested.id)) == 2


async def test_engine_defensively_gates_constructed_privileged_bypass() -> None:
    bypass = RecommendedAction.model_construct(
        action_type=ResponseActionType.BLOCK_IP,
        rationale="Attempt to bypass schema validation in a synthetic test.",
        requires_approval=False,
    )
    engine = ResponseEngine(InMemoryApprovalStore())

    record = await engine.request_action(bypass)

    assert record.approval_status is ApprovalStatus.PENDING
    assert record.execution_status is ExecutionStatus.NOT_EXECUTED
    assert record.result is None
    assert record.action.requires_approval is True


@pytest.mark.parametrize("action_type", sorted(RecommendedAction.PRIVILEGED_ACTIONS))
async def test_every_constructed_privileged_action_is_defensively_gated(
    action_type: ResponseActionType,
) -> None:
    bypass = RecommendedAction.model_construct(
        action_type=action_type,
        rationale="Synthetic constructed input.",
        requires_approval=False,
    )

    record = await ResponseEngine(InMemoryApprovalStore()).request_action(bypass)

    assert record.approval_status is ApprovalStatus.PENDING
    assert record.execution_status is ExecutionStatus.NOT_EXECUTED
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
async def test_every_action_type_has_a_sane_simulated_handler(
    action_type: ResponseActionType, expected_text: str
) -> None:
    incident, event = incident_and_evidence()
    engine = ResponseEngine(InMemoryApprovalStore())
    requires_approval = action_type in RecommendedAction.PRIVILEGED_ACTIONS
    record = await engine.request_action(
        action(action_type, requires_approval=requires_approval),
        incident.id,
        action_context_from_incident(incident, [event]),
    )
    if record.approval_status is ApprovalStatus.PENDING:
        record = await engine.approve(record.id, decided_by="analyst-01")

    assert record.execution_status is ExecutionStatus.SIMULATED
    assert record.result is not None
    assert expected_text in record.result.description
    assert record.result.details["mode"] == "simulation"


async def test_malformed_target_is_a_failed_simulation() -> None:
    engine = ResponseEngine(InMemoryApprovalStore())
    requested = await engine.request_action(
        action(ResponseActionType.QUARANTINE_DEVICE, requires_approval=True)
    )

    record = await engine.approve(requested.id, decided_by="analyst-01")

    assert record.execution_status is ExecutionStatus.FAILED
    assert record.result is not None
    assert "device MAC address is missing" in record.result.description


@pytest.mark.parametrize(
    ("configured", "real_execution", "expected_mode"),
    [
        (False, False, "simulation"),
        (False, True, "simulation"),
        (True, False, "simulation"),
        (True, True, "real"),
    ],
)
async def test_packetfence_two_signal_gate(
    monkeypatch: pytest.MonkeyPatch,
    configured: bool,
    real_execution: bool,
    expected_mode: str,
) -> None:
    monkeypatch.setattr(response_module, "PacketFenceClient", StubPacketFenceClient)
    StubPacketFenceClient.calls = []
    StubPacketFenceClient.error = None
    if configured:
        monkeypatch.setenv("PACKETFENCE_BASE_URL", "https://10.20.30.40:9999")
        monkeypatch.setenv("PACKETFENCE_API_TOKEN", "synthetic-api-token")
    else:
        monkeypatch.delenv("PACKETFENCE_BASE_URL", raising=False)
        monkeypatch.delenv("PACKETFENCE_API_TOKEN", raising=False)
    monkeypatch.setenv("PACKETFENCE_REAL_EXECUTION", str(real_execution).lower())
    incident, event = incident_and_evidence()

    result = await QuarantineDeviceHandler().simulate(
        action(ResponseActionType.QUARANTINE_DEVICE, requires_approval=True),
        action_context_from_incident(incident, [event]),
        incident.id,
    )

    assert result.details["mode"] == expected_mode
    assert StubPacketFenceClient.calls == (
        ["AA:BB:CC:DD:EE:FF"] if expected_mode == "real" else []
    )
    if expected_mode == "real":
        assert result.details["status_code"] == 200
        assert result.details["node_status"] == "unreg"
        assert result.details["isolation_confirmed"] is True


async def test_packetfence_failure_becomes_explainable_audit_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(response_module, "PacketFenceClient", StubPacketFenceClient)
    monkeypatch.setenv("PACKETFENCE_BASE_URL", "https://10.20.30.40:9999")
    monkeypatch.setenv("PACKETFENCE_API_TOKEN", "synthetic-api-token")
    monkeypatch.setenv("PACKETFENCE_REAL_EXECUTION", "true")
    StubPacketFenceClient.calls = []
    StubPacketFenceClient.error = PacketFenceError(
        "PacketFence isolation request returned HTTP 503", status_code=503
    )
    incident, event = incident_and_evidence()
    engine = ResponseEngine(InMemoryApprovalStore())
    requested = await engine.request_action(
        action(ResponseActionType.QUARANTINE_DEVICE, requires_approval=True),
        incident.id,
        action_context_from_incident(incident, [event]),
    )

    record = await engine.approve(requested.id, decided_by="analyst-01")

    assert record.execution_status is ExecutionStatus.FAILED
    assert record.result is not None
    assert record.result.details["mode"] == "real"
    assert record.result.details["status_code"] == 503
    assert "HTTP 503" in record.result.description
