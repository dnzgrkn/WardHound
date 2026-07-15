from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import uuid4

import httpx
import pytest
from ldap3 import MOCK_SYNC, Connection, Server

import app.engines.response as response_module
from app.engines.response import (
    BlockIpHandler,
    CloseSessionHandler,
    CreateIncidentHandler,
    DisableUserHandler,
    InMemoryApprovalStore,
    NotifyAdministratorHandler,
    QuarantineDeviceHandler,
    RequireMfaHandler,
    ResponseEngine,
    action_context_from_incident,
)
from app.integrations.active_directory import (
    AD_ACCOUNTDISABLE,
    ActiveDirectoryClient,
    ActiveDirectoryError,
    DisableAccountResult,
)
from app.integrations.duo import DuoError, DuoVerificationResult
from app.integrations.firepower import BlockIpResult, FirepowerError
from app.integrations.jumpserver import (
    JumpServerError,
    TerminateSessionResult,
)
from app.integrations.packetfence import PacketFenceError, PacketFenceIsolationResult
from app.integrations.ticketing import (
    TicketCreationResult,
    TicketingError,
)
from app.integrations.webhook import WebhookClient, WebhookError
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
from app.schemas.response import ActionContext, ApprovalStatus, ExecutionStatus


class StubPacketFenceClient:
    calls: list[tuple[str, str]] = []
    error: PacketFenceError | None = None

    def __init__(self, base_url: str, api_token: str) -> None:
        assert base_url == "https://10.20.30.40:9999"
        assert api_token == "synthetic-api-token"

    async def __aenter__(self) -> StubPacketFenceClient:
        return self

    async def __aexit__(self, *args: object) -> None:
        return None

    async def isolate_node(
        self, mac_address: str, security_event_id: str
    ) -> PacketFenceIsolationResult:
        self.calls.append((mac_address, security_event_id))
        if self.error is not None:
            raise self.error
        return PacketFenceIsolationResult(status_code=200, security_event_record_id=42)


class StubActiveDirectoryClient:
    calls: list[str] = []
    error: ActiveDirectoryError | None = None

    def __init__(
        self,
        ldap_url: str,
        bind_dn: str,
        bind_password: str,
        search_base_dn: str,
    ) -> None:
        assert ldap_url == "ldaps://dc01.corp.example.com:636"
        assert bind_dn == BIND_DN
        assert bind_password == "synthetic-bind-password"
        assert search_base_dn == "OU=Users,DC=corp,DC=example,DC=com"

    async def disable_user(self, sam_account_name: str) -> DisableAccountResult:
        self.calls.append(sam_account_name)
        if self.error is not None:
            raise self.error
        return DisableAccountResult(already_disabled=False)


class StubFirepowerClient:
    calls: list[tuple[str, str]] = []
    error: FirepowerError | None = None

    def __init__(self, base_url: str, username: str, password: str) -> None:
        assert base_url == "https://fmc.corp.example.com"
        assert username == "synthetic-api-user"
        assert password == "synthetic-api-password"

    async def __aenter__(self) -> StubFirepowerClient:
        return self

    async def __aexit__(self, *args: object) -> None:
        return None

    async def add_blocklist_member(
        self, network_group_id: str, target_ip: str
    ) -> BlockIpResult:
        self.calls.append((network_group_id, target_ip))
        if self.error is not None:
            raise self.error
        return BlockIpResult(already_blocked=False)


class StubDuoClient:
    calls: list[str] = []
    error: DuoError | None = None

    def __init__(self, api_hostname: str, integration_key: str, secret_key: str) -> None:
        assert api_hostname == "api-synthetic.duosecurity.com"
        assert integration_key == "DIXXXXXXXXXXXXXXXXXX"
        assert secret_key == "synthetic-secret-key"

    async def __aenter__(self) -> StubDuoClient:
        return self

    async def __aexit__(self, *args: object) -> None:
        return None

    async def require_verification(self, username: str) -> DuoVerificationResult:
        self.calls.append(username)
        if self.error is not None:
            raise self.error
        return DuoVerificationResult()


class StubJumpServerClient:
    calls: list[str] = []
    error: JumpServerError | None = None

    def __init__(self, base_url: str, api_token: str) -> None:
        assert base_url == "https://jumpserver.corp.example.com"
        assert api_token == "synthetic-api-token"

    async def __aenter__(self) -> StubJumpServerClient:
        return self

    async def __aexit__(self, *args: object) -> None:
        return None

    async def terminate_session(self, session_id: str) -> TerminateSessionResult:
        self.calls.append(session_id)
        if self.error is not None:
            raise self.error
        return TerminateSessionResult()


class StubWebhookClient:
    calls: list[tuple[object, str, str]] = []
    error: WebhookError | None = None

    def __init__(self, webhook_url: str) -> None:
        assert webhook_url == "https://hooks.example.com/services/synthetic-token"

    async def __aenter__(self) -> StubWebhookClient:
        return self

    async def __aexit__(self, *args: object) -> None:
        return None

    async def send_notification(
        self,
        incident_id: object,
        severity: str,
        rationale: str,
        timestamp: datetime,
    ) -> int:
        assert timestamp.tzinfo is UTC
        self.calls.append((incident_id, severity, rationale))
        if self.error is not None:
            raise self.error
        return 200


class StubTicketingClient:
    calls: list[tuple[str, str, object, str]] = []
    error: TicketingError | None = None

    def __init__(self, webhook_url: str) -> None:
        assert webhook_url == "https://tickets.example.com/hooks/synthetic-token"

    async def __aenter__(self) -> StubTicketingClient:
        return self

    async def __aexit__(self, *args: object) -> None:
        return None

    async def create_ticket(
        self,
        title: str,
        description: str,
        incident_id: object,
        severity: str,
    ) -> TicketCreationResult:
        self.calls.append((title, description, incident_id, severity))
        if self.error is not None:
            raise self.error
        return TicketCreationResult(ticket_id="TKT-SYNTHETIC-0017", status_code=201)


BIND_DN = "CN=svc-wardhound,OU=Service Accounts,DC=corp,DC=example,DC=com"


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
    ("connection_configured", "event_configured", "real_execution", "expected_mode"),
    [
        (False, False, False, "simulation"),
        (False, True, True, "simulation"),
        (True, False, True, "simulation"),
        (True, True, False, "simulation"),
        (True, True, True, "real"),
    ],
)
async def test_packetfence_execution_gate_requires_all_configuration(
    monkeypatch: pytest.MonkeyPatch,
    connection_configured: bool,
    event_configured: bool,
    real_execution: bool,
    expected_mode: str,
) -> None:
    monkeypatch.setattr(response_module, "PacketFenceClient", StubPacketFenceClient)
    StubPacketFenceClient.calls = []
    StubPacketFenceClient.error = None
    if connection_configured:
        monkeypatch.setenv("PACKETFENCE_BASE_URL", "https://10.20.30.40:9999")
        monkeypatch.setenv("PACKETFENCE_API_TOKEN", "synthetic-api-token")
    else:
        monkeypatch.delenv("PACKETFENCE_BASE_URL", raising=False)
        monkeypatch.delenv("PACKETFENCE_API_TOKEN", raising=False)
    if event_configured:
        monkeypatch.setenv(
            "PACKETFENCE_ISOLATION_SECURITY_EVENT_ID", "synthetic-isolation-event"
        )
    else:
        monkeypatch.delenv("PACKETFENCE_ISOLATION_SECURITY_EVENT_ID", raising=False)
    monkeypatch.setenv("PACKETFENCE_REAL_EXECUTION", str(real_execution).lower())
    incident, event = incident_and_evidence()

    result = await QuarantineDeviceHandler().simulate(
        action(ResponseActionType.QUARANTINE_DEVICE, requires_approval=True),
        action_context_from_incident(incident, [event]),
        incident.id,
    )

    assert result.details["mode"] == expected_mode
    assert StubPacketFenceClient.calls == (
        [("AA:BB:CC:DD:EE:FF", "synthetic-isolation-event")]
        if expected_mode == "real"
        else []
    )
    if expected_mode == "real":
        assert result.details["status_code"] == 200
        assert result.details["security_event_record_id"] == 42
        assert result.details["isolation_confirmed"] is True


async def test_packetfence_failure_becomes_explainable_audit_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(response_module, "PacketFenceClient", StubPacketFenceClient)
    monkeypatch.setenv("PACKETFENCE_BASE_URL", "https://10.20.30.40:9999")
    monkeypatch.setenv("PACKETFENCE_API_TOKEN", "synthetic-api-token")
    monkeypatch.setenv(
        "PACKETFENCE_ISOLATION_SECURITY_EVENT_ID", "synthetic-isolation-event"
    )
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


@pytest.mark.parametrize(
    "missing_variable",
    [
        "AD_LDAP_URL",
        "AD_BIND_DN",
        "AD_BIND_PASSWORD",
        "AD_USER_SEARCH_BASE_DN",
        "AD_REAL_EXECUTION",
        None,
    ],
)
async def test_active_directory_execution_gate_requires_all_five_signals(
    monkeypatch: pytest.MonkeyPatch,
    missing_variable: str | None,
) -> None:
    monkeypatch.setattr(
        response_module, "ActiveDirectoryClient", StubActiveDirectoryClient
    )
    configuration = {
        "AD_LDAP_URL": "ldaps://dc01.corp.example.com:636",
        "AD_BIND_DN": BIND_DN,
        "AD_BIND_PASSWORD": "synthetic-bind-password",
        "AD_USER_SEARCH_BASE_DN": "OU=Users,DC=corp,DC=example,DC=com",
        "AD_REAL_EXECUTION": "true",
    }
    for name, value in configuration.items():
        monkeypatch.setenv(name, value)
    if missing_variable is not None:
        if missing_variable == "AD_REAL_EXECUTION":
            monkeypatch.setenv(missing_variable, "false")
        else:
            monkeypatch.delenv(missing_variable)
    StubActiveDirectoryClient.calls = []
    StubActiveDirectoryClient.error = None
    incident, event = incident_and_evidence()

    result = await DisableUserHandler().simulate(
        action(ResponseActionType.DISABLE_USER, requires_approval=True),
        action_context_from_incident(incident, [event]),
        incident.id,
    )

    expected_mode = "real" if missing_variable is None else "simulation"
    assert result.details["mode"] == expected_mode
    assert StubActiveDirectoryClient.calls == (["jdoe"] if expected_mode == "real" else [])
    if expected_mode == "real":
        assert result.details["operation"] == "disable_account"
        assert result.details["disable_confirmed"] is True
        assert result.details["already_disabled"] is False


async def test_active_directory_failure_becomes_explainable_audit_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        response_module, "ActiveDirectoryClient", StubActiveDirectoryClient
    )
    monkeypatch.setenv("AD_LDAP_URL", "ldaps://dc01.corp.example.com:636")
    monkeypatch.setenv("AD_BIND_DN", BIND_DN)
    monkeypatch.setenv("AD_BIND_PASSWORD", "synthetic-bind-password")
    monkeypatch.setenv("AD_USER_SEARCH_BASE_DN", "OU=Users,DC=corp,DC=example,DC=com")
    monkeypatch.setenv("AD_REAL_EXECUTION", "true")
    StubActiveDirectoryClient.calls = []
    StubActiveDirectoryClient.error = ActiveDirectoryError("Active Directory bind failed")
    incident, event = incident_and_evidence()
    engine = ResponseEngine(InMemoryApprovalStore())
    requested = await engine.request_action(
        action(ResponseActionType.DISABLE_USER, requires_approval=True),
        incident.id,
        action_context_from_incident(incident, [event]),
    )

    record = await engine.approve(requested.id, decided_by="analyst-01")

    assert record.execution_status is ExecutionStatus.FAILED
    assert record.result is not None
    assert record.result.details == {
        "integration": "active_directory",
        "operation": "disable_account",
        "mode": "real",
        "error": "Active Directory bind failed",
    }


async def test_active_directory_real_audit_uses_confirmed_mock_directory_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user_dn = "CN=jdoe,OU=Users,DC=corp,DC=example,DC=com"
    connection = Connection(
        Server("dc01.corp.example.com"),
        user=BIND_DN,
        password="synthetic-bind-password",
        client_strategy=MOCK_SYNC,
    )
    connection.strategy.add_entry(
        BIND_DN,
        {"objectClass": ["person"], "userPassword": "synthetic-bind-password"},
    )
    connection.strategy.add_entry(
        user_dn,
        {
            "objectClass": ["top", "person", "organizationalPerson", "user"],
            "sAMAccountName": "jdoe",
            "userAccountControl": 512,
        },
    )

    def mock_client(
        ldap_url: str,
        bind_dn: str,
        bind_password: str,
        search_base_dn: str,
    ) -> ActiveDirectoryClient:
        return ActiveDirectoryClient(
            ldap_url,
            bind_dn,
            bind_password,
            search_base_dn,
            connection=connection,
        )

    monkeypatch.setattr(response_module, "ActiveDirectoryClient", mock_client)
    monkeypatch.setenv("AD_LDAP_URL", "ldaps://dc01.corp.example.com:636")
    monkeypatch.setenv("AD_BIND_DN", BIND_DN)
    monkeypatch.setenv("AD_BIND_PASSWORD", "synthetic-bind-password")
    monkeypatch.setenv("AD_USER_SEARCH_BASE_DN", "OU=Users,DC=corp,DC=example,DC=com")
    monkeypatch.setenv("AD_REAL_EXECUTION", "true")
    incident, event = incident_and_evidence()
    engine = ResponseEngine(InMemoryApprovalStore())
    requested = await engine.request_action(
        action(ResponseActionType.DISABLE_USER, requires_approval=True),
        incident.id,
        action_context_from_incident(incident, [event]),
    )

    record = await engine.approve(requested.id, decided_by="analyst-01")

    assert record.result is not None
    assert record.result.details["mode"] == "real"
    assert record.result.details["disable_confirmed"] is True
    assert int(connection.strategy.entries[user_dn]["userAccountControl"][0]) & AD_ACCOUNTDISABLE


@pytest.mark.parametrize(
    "missing_variable",
    [
        "FMC_BASE_URL",
        "FMC_USERNAME",
        "FMC_PASSWORD",
        "FMC_BLOCKLIST_NETWORK_GROUP_ID",
        "FMC_REAL_EXECUTION",
        None,
    ],
)
async def test_fmc_execution_gate_requires_all_five_signals(
    monkeypatch: pytest.MonkeyPatch,
    missing_variable: str | None,
) -> None:
    monkeypatch.setattr(response_module, "FirepowerClient", StubFirepowerClient)
    configuration = {
        "FMC_BASE_URL": "https://fmc.corp.example.com",
        "FMC_USERNAME": "synthetic-api-user",
        "FMC_PASSWORD": "synthetic-api-password",
        "FMC_BLOCKLIST_NETWORK_GROUP_ID": "group-synthetic-0042",
        "FMC_REAL_EXECUTION": "true",
    }
    for name, value in configuration.items():
        monkeypatch.setenv(name, value)
    if missing_variable is not None:
        if missing_variable == "FMC_REAL_EXECUTION":
            monkeypatch.setenv(missing_variable, "false")
        else:
            monkeypatch.delenv(missing_variable)
    StubFirepowerClient.calls = []
    StubFirepowerClient.error = None
    incident, event = incident_and_evidence()

    result = await BlockIpHandler().simulate(
        action(ResponseActionType.BLOCK_IP, requires_approval=True),
        action_context_from_incident(incident, [event]),
        incident.id,
    )

    expected_mode = "real" if missing_variable is None else "simulation"
    assert result.details["mode"] == expected_mode
    assert StubFirepowerClient.calls == (
        [("group-synthetic-0042", "10.20.30.40")] if expected_mode == "real" else []
    )
    if expected_mode == "real":
        assert result.details["operation"] == "add_blocklist_member"
        assert result.details["membership_confirmed"] is True
        assert result.details["enforcement_pending_deploy"] is True


async def test_fmc_failure_becomes_explainable_audit_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(response_module, "FirepowerClient", StubFirepowerClient)
    monkeypatch.setenv("FMC_BASE_URL", "https://fmc.corp.example.com")
    monkeypatch.setenv("FMC_USERNAME", "synthetic-api-user")
    monkeypatch.setenv("FMC_PASSWORD", "synthetic-api-password")
    monkeypatch.setenv("FMC_BLOCKLIST_NETWORK_GROUP_ID", "group-synthetic-0042")
    monkeypatch.setenv("FMC_REAL_EXECUTION", "true")
    StubFirepowerClient.calls = []
    StubFirepowerClient.error = FirepowerError(
        "FMC network-group update returned HTTP 422", status_code=422
    )
    incident, event = incident_and_evidence()
    engine = ResponseEngine(InMemoryApprovalStore())
    requested = await engine.request_action(
        action(ResponseActionType.BLOCK_IP, requires_approval=True),
        incident.id,
        action_context_from_incident(incident, [event]),
    )

    record = await engine.approve(requested.id, decided_by="analyst-01")

    assert record.execution_status is ExecutionStatus.FAILED
    assert record.result is not None
    assert record.result.details["mode"] == "real"
    assert record.result.details["status_code"] == 422


@pytest.mark.parametrize(
    "missing_variable",
    [
        "JUMPSERVER_BASE_URL",
        "JUMPSERVER_API_TOKEN",
        "JUMPSERVER_REAL_EXECUTION",
        None,
    ],
)
async def test_jumpserver_execution_gate_requires_all_three_signals(
    monkeypatch: pytest.MonkeyPatch,
    missing_variable: str | None,
) -> None:
    monkeypatch.setattr(response_module, "JumpServerClient", StubJumpServerClient)
    configuration = {
        "JUMPSERVER_BASE_URL": "https://jumpserver.corp.example.com",
        "JUMPSERVER_API_TOKEN": "synthetic-api-token",
        "JUMPSERVER_REAL_EXECUTION": "true",
    }
    for name, value in configuration.items():
        monkeypatch.setenv(name, value)
    if missing_variable is not None:
        if missing_variable == "JUMPSERVER_REAL_EXECUTION":
            monkeypatch.setenv(missing_variable, "false")
        else:
            monkeypatch.delenv(missing_variable)
    StubJumpServerClient.calls = []
    StubJumpServerClient.error = None
    incident, event = incident_and_evidence()

    result = await CloseSessionHandler().simulate(
        action(ResponseActionType.CLOSE_SESSION, requires_approval=True),
        action_context_from_incident(incident, [event]),
        incident.id,
    )

    expected_mode = "real" if missing_variable is None else "simulation"
    assert result.details["mode"] == expected_mode
    assert StubJumpServerClient.calls == (
        ["session-synthetic-0042"] if expected_mode == "real" else []
    )
    if expected_mode == "real":
        assert result.details["operation"] == "terminate_session"
        assert result.details["termination_confirmed"] is True
        assert result.details["is_finished"] is True


async def test_jumpserver_failure_becomes_explainable_audit_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(response_module, "JumpServerClient", StubJumpServerClient)
    monkeypatch.setenv("JUMPSERVER_BASE_URL", "https://jumpserver.corp.example.com")
    monkeypatch.setenv("JUMPSERVER_API_TOKEN", "synthetic-api-token")
    monkeypatch.setenv("JUMPSERVER_REAL_EXECUTION", "true")
    StubJumpServerClient.calls = []
    StubJumpServerClient.error = JumpServerError(
        "JumpServer session termination returned HTTP 403", status_code=403
    )
    incident, event = incident_and_evidence()
    engine = ResponseEngine(InMemoryApprovalStore())
    requested = await engine.request_action(
        action(ResponseActionType.CLOSE_SESSION, requires_approval=True),
        incident.id,
        action_context_from_incident(incident, [event]),
    )

    record = await engine.approve(requested.id, decided_by="analyst-01")

    assert record.execution_status is ExecutionStatus.FAILED
    assert record.result is not None
    assert record.result.details["mode"] == "real"
    assert record.result.details["status_code"] == 403


@pytest.mark.parametrize(
    "missing_variable",
    [
        "DUO_API_HOSTNAME",
        "DUO_INTEGRATION_KEY",
        "DUO_SECRET_KEY",
        "DUO_REAL_EXECUTION",
        None,
    ],
)
async def test_duo_execution_gate_requires_all_four_signals(
    monkeypatch: pytest.MonkeyPatch,
    missing_variable: str | None,
) -> None:
    monkeypatch.setattr(response_module, "DuoClient", StubDuoClient)
    configuration = {
        "DUO_API_HOSTNAME": "api-synthetic.duosecurity.com",
        "DUO_INTEGRATION_KEY": "DIXXXXXXXXXXXXXXXXXX",
        "DUO_SECRET_KEY": "synthetic-secret-key",
        "DUO_REAL_EXECUTION": "true",
    }
    for name, value in configuration.items():
        monkeypatch.setenv(name, value)
    if missing_variable is not None:
        if missing_variable == "DUO_REAL_EXECUTION":
            monkeypatch.setenv(missing_variable, "false")
        else:
            monkeypatch.delenv(missing_variable)
    StubDuoClient.calls = []
    StubDuoClient.error = None
    incident, event = incident_and_evidence()

    result = await RequireMfaHandler().simulate(
        action(ResponseActionType.REQUIRE_MFA, requires_approval=True),
        action_context_from_incident(incident, [event]),
        incident.id,
    )

    expected_mode = "real" if missing_variable is None else "simulation"
    assert result.details["mode"] == expected_mode
    assert StubDuoClient.calls == (["jdoe"] if expected_mode == "real" else [])
    if expected_mode == "real":
        assert result.details["operation"] == "send_verification_push"
        assert result.details["verification_confirmed"] is True


async def test_duo_failure_becomes_explainable_audit_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(response_module, "DuoClient", StubDuoClient)
    monkeypatch.setenv("DUO_API_HOSTNAME", "api-synthetic.duosecurity.com")
    monkeypatch.setenv("DUO_INTEGRATION_KEY", "DIXXXXXXXXXXXXXXXXXX")
    monkeypatch.setenv("DUO_SECRET_KEY", "synthetic-secret-key")
    monkeypatch.setenv("DUO_REAL_EXECUTION", "true")
    StubDuoClient.calls = []
    StubDuoClient.error = DuoError("Duo user lookup returned HTTP 401", status_code=401)
    incident, event = incident_and_evidence()
    engine = ResponseEngine(InMemoryApprovalStore())
    requested = await engine.request_action(
        action(ResponseActionType.REQUIRE_MFA, requires_approval=True),
        incident.id,
        action_context_from_incident(incident, [event]),
    )

    record = await engine.approve(requested.id, decided_by="analyst-01")

    assert record.execution_status is ExecutionStatus.FAILED
    assert record.result is not None
    assert record.result.details["mode"] == "real"
    assert record.result.details["status_code"] == 401


@pytest.mark.parametrize(
    ("webhook_url", "real_execution", "expected_mode"),
    [
        ("", "false", "simulation"),
        ("", "true", "simulation"),
        ("https://hooks.example.com/services/synthetic-token", "false", "simulation"),
        ("https://hooks.example.com/services/synthetic-token", "not-true", "simulation"),
        ("https://hooks.example.com/services/synthetic-token", "true", "real"),
    ],
)
async def test_webhook_execution_gate_requires_both_signals(
    monkeypatch: pytest.MonkeyPatch,
    webhook_url: str,
    real_execution: str,
    expected_mode: str,
) -> None:
    monkeypatch.setattr(response_module, "WebhookClient", StubWebhookClient)
    if webhook_url:
        monkeypatch.setenv("NOTIFY_WEBHOOK_URL", webhook_url)
    else:
        monkeypatch.delenv("NOTIFY_WEBHOOK_URL", raising=False)
    monkeypatch.setenv("NOTIFY_REAL_EXECUTION", real_execution)
    StubWebhookClient.calls = []
    StubWebhookClient.error = None
    incident, _ = incident_and_evidence()
    recommendation = action(
        ResponseActionType.NOTIFY_ADMINISTRATOR, requires_approval=False
    )

    result = await NotifyAdministratorHandler().simulate(
        recommendation, ActionContext(), incident.id
    )

    assert result.details["mode"] == expected_mode
    assert result.details["operation"] == "send_webhook_notification"
    assert StubWebhookClient.calls == (
        [(incident.id, "unknown", recommendation.rationale)]
        if expected_mode == "real"
        else []
    )
    if expected_mode == "real":
        assert result.details["status_code"] == 200


async def test_webhook_failure_becomes_explainable_audit_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(response_module, "WebhookClient", StubWebhookClient)
    monkeypatch.setenv(
        "NOTIFY_WEBHOOK_URL", "https://hooks.example.com/services/synthetic-token"
    )
    monkeypatch.setenv("NOTIFY_REAL_EXECUTION", "true")
    StubWebhookClient.calls = []
    StubWebhookClient.error = WebhookError(
        "Administrator notification webhook returned HTTP 503", status_code=503
    )
    incident, _ = incident_and_evidence()
    engine = ResponseEngine(InMemoryApprovalStore())

    record = await engine.request_action(
        action(ResponseActionType.NOTIFY_ADMINISTRATOR, requires_approval=False), incident.id
    )

    assert record.execution_status is ExecutionStatus.FAILED
    assert record.result is not None
    assert record.result.details["mode"] == "real"
    assert record.result.details["operation"] == "send_webhook_notification"
    assert record.result.details["status_code"] == 503


async def test_webhook_payload_excludes_raw_context_and_url_credential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    webhook_url = "https://hooks.example.com/services/synthetic-url-credential"
    raw_event_marker = "RAW_EVENT_DUMP=password-synthetic-secret"
    captured_body = b""

    def request_handler(request: httpx.Request) -> httpx.Response:
        nonlocal captured_body
        captured_body = request.content
        return httpx.Response(200)

    transport = httpx.MockTransport(request_handler)

    def client_factory(configured_url: str) -> WebhookClient:
        assert configured_url == webhook_url
        return WebhookClient(configured_url, transport=transport)

    monkeypatch.setattr(response_module, "WebhookClient", client_factory)
    monkeypatch.setenv("NOTIFY_WEBHOOK_URL", webhook_url)
    monkeypatch.setenv("NOTIFY_REAL_EXECUTION", "true")
    incident, _ = incident_and_evidence()

    result = await NotifyAdministratorHandler().simulate(
        action(ResponseActionType.NOTIFY_ADMINISTRATOR, requires_approval=False),
        ActionContext(session_id=raw_event_marker),
        incident.id,
    )

    outgoing_payload = json.loads(captured_body)
    serialized_payload = json.dumps(outgoing_payload)
    assert result.details["mode"] == "real"
    assert raw_event_marker not in serialized_payload
    assert "synthetic-url-credential" not in serialized_payload
    assert webhook_url not in serialized_payload
    assert set(outgoing_payload) == {"text"}


@pytest.mark.parametrize(
    ("webhook_url", "real_execution", "expected_mode"),
    [
        ("", "false", "simulation"),
        ("", "true", "simulation"),
        ("https://tickets.example.com/hooks/synthetic-token", "false", "simulation"),
        ("https://tickets.example.com/hooks/synthetic-token", "not-true", "simulation"),
        ("https://tickets.example.com/hooks/synthetic-token", "true", "real"),
    ],
)
async def test_ticketing_execution_gate_requires_both_signals(
    monkeypatch: pytest.MonkeyPatch,
    webhook_url: str,
    real_execution: str,
    expected_mode: str,
) -> None:
    monkeypatch.setattr(response_module, "TicketingClient", StubTicketingClient)
    if webhook_url:
        monkeypatch.setenv("TICKETING_WEBHOOK_URL", webhook_url)
    else:
        monkeypatch.delenv("TICKETING_WEBHOOK_URL", raising=False)
    monkeypatch.setenv("TICKETING_REAL_EXECUTION", real_execution)
    StubTicketingClient.calls = []
    StubTicketingClient.error = None
    incident, _ = incident_and_evidence()
    recommendation = action(ResponseActionType.CREATE_INCIDENT, requires_approval=False)

    result = await CreateIncidentHandler().simulate(
        recommendation, ActionContext(), incident.id
    )

    assert result.details["mode"] == expected_mode
    assert result.details["operation"] == "create_ticket"
    assert StubTicketingClient.calls == (
        [
            (
                f"WardHound incident {incident.id}",
                recommendation.rationale,
                incident.id,
                "unknown",
            )
        ]
        if expected_mode == "real"
        else []
    )
    if expected_mode == "real":
        assert result.details["status_code"] == 201
        assert result.details["ticket_id"] == "TKT-SYNTHETIC-0017"


async def test_ticketing_failure_becomes_explainable_audit_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(response_module, "TicketingClient", StubTicketingClient)
    monkeypatch.setenv(
        "TICKETING_WEBHOOK_URL", "https://tickets.example.com/hooks/synthetic-token"
    )
    monkeypatch.setenv("TICKETING_REAL_EXECUTION", "true")
    StubTicketingClient.calls = []
    StubTicketingClient.error = TicketingError(
        "Ticketing webhook response did not return a ticket identifier", status_code=200
    )
    incident, _ = incident_and_evidence()
    engine = ResponseEngine(InMemoryApprovalStore())

    record = await engine.request_action(
        action(ResponseActionType.CREATE_INCIDENT, requires_approval=False), incident.id
    )

    assert record.execution_status is ExecutionStatus.FAILED
    assert record.result is not None
    assert record.result.details["mode"] == "real"
    assert record.result.details["operation"] == "create_ticket"
    assert record.result.details["status_code"] == 200
