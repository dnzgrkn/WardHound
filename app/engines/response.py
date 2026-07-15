"""Human-gated response workflow with safe-by-default action handlers."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID

from app.config.secrets import default_secret_provider
from app.integrations.active_directory import ActiveDirectoryClient, ActiveDirectoryError
from app.integrations.duo import DuoClient, DuoError
from app.integrations.firepower import FirepowerClient, FirepowerError
from app.integrations.jumpserver import JumpServerClient, JumpServerError
from app.integrations.packetfence import PacketFenceClient, PacketFenceError
from app.integrations.ticketing import TicketingClient, TicketingError
from app.integrations.webhook import WebhookClient, WebhookError
from app.schemas.analysis import RecommendedAction, ResponseActionType
from app.schemas.events import EntityType, NormalizedEvent, SourceSystem
from app.schemas.incidents import Incident
from app.schemas.response import (
    ActionAuditRecord,
    ActionContext,
    ApprovalStatus,
    ExecutionStatus,
    SimulatedActionResult,
)


class ActionRecordNotFoundError(LookupError):
    """Raised when an approval decision references an unknown audit record."""


class InvalidActionTransitionError(ValueError):
    """Raised when a decision is not valid for the record's current state."""


class SimulationTargetError(ValueError):
    """Raised by a simulated handler when its required target is unavailable."""


class ActionExecutionError(RuntimeError):
    """Raised when an enabled real integration fails cleanly."""

    def __init__(self, message: str, *, details: dict[str, object]) -> None:
        super().__init__(message)
        self.details = details


class ApprovalStore(Protocol):
    """Persistence seam for immutable response lifecycle snapshots."""

    async def append(self, record: ActionAuditRecord) -> None:
        """Append a new snapshot for a request without altering earlier snapshots."""
        ...

    async def get(self, record_id: UUID) -> ActionAuditRecord | None:
        """Return the latest snapshot for a request, if it exists."""
        ...

    async def history(self, record_id: UUID) -> tuple[ActionAuditRecord, ...]:
        """Return every snapshot for a request in append order."""
        ...

    async def list_for_incident(self, incident_id: UUID) -> list[ActionAuditRecord]:
        """Return the latest snapshot of every request linked to an incident."""
        ...


class InMemoryApprovalStore:
    """Dict-backed Stage 5 store used in tests and local simulations."""

    def __init__(self) -> None:
        self._records: dict[UUID, list[ActionAuditRecord]] = {}

    async def append(self, record: ActionAuditRecord) -> None:
        self._records.setdefault(record.id, []).append(record)

    async def get(self, record_id: UUID) -> ActionAuditRecord | None:
        snapshots = self._records.get(record_id)
        return snapshots[-1] if snapshots else None

    async def history(self, record_id: UUID) -> tuple[ActionAuditRecord, ...]:
        return tuple(self._records.get(record_id, ()))

    async def list_for_incident(self, incident_id: UUID) -> list[ActionAuditRecord]:
        return [
            snapshots[-1]
            for snapshots in self._records.values()
            if snapshots and snapshots[-1].incident_id == incident_id
        ]


class SimulatedActionHandler(Protocol):
    """Extension point implemented by one simulator per response action type."""

    action_type: ResponseActionType

    async def simulate(
        self,
        action: RecommendedAction,
        context: ActionContext,
        incident_id: UUID | None,
        *,
        decided_by: str | None = None,
        decided_at: datetime | None = None,
    ) -> SimulatedActionResult:
        """Execute or describe the registered response behavior."""
        ...


class QuarantineDeviceHandler:
    action_type = ResponseActionType.QUARANTINE_DEVICE

    async def simulate(
        self,
        action: RecommendedAction,
        context: ActionContext,
        incident_id: UUID | None,
        *,
        decided_by: str | None = None,
        decided_at: datetime | None = None,
    ) -> SimulatedActionResult:
        target = _device_mac(context)
        base_url = (await default_secret_provider.get("PACKETFENCE_BASE_URL") or "").strip()
        api_token = (await default_secret_provider.get("PACKETFENCE_API_TOKEN") or "").strip()
        security_event_id = (
            await default_secret_provider.get("PACKETFENCE_ISOLATION_SECURITY_EVENT_ID") or ""
        ).strip()
        real_execution = (
            (await default_secret_provider.get("PACKETFENCE_REAL_EXECUTION") or "")
            .strip()
            .casefold()
            == "true"
        )
        if base_url and api_token and security_event_id and real_execution:
            try:
                async with PacketFenceClient(base_url, api_token) as client:
                    outcome = await client.isolate_node(target, security_event_id)
            except PacketFenceError as exc:
                details: dict[str, object] = {
                    "integration": "packetfence",
                    "operation": "apply_security_event",
                    "mode": "real",
                    "error": str(exc),
                }
                if exc.status_code is not None:
                    details["status_code"] = exc.status_code
                raise ActionExecutionError(str(exc), details=details) from exc
            details = {
                "integration": "packetfence",
                "operation": "apply_security_event",
                "mode": "real",
                "status_code": outcome.status_code,
                "security_event_record_id": outcome.security_event_record_id,
                "isolation_confirmed": True,
            }
            return SimulatedActionResult(
                description=f"PacketFence isolated MAC {target}.",
                target_identifier=target,
                details=details,
            )
        return _result(
            f"Would set PacketFence node status to isolated for MAC {target}.",
            target,
            integration="packetfence",
            operation="apply_security_event",
        )


class DisableUserHandler:
    action_type = ResponseActionType.DISABLE_USER

    async def simulate(
        self,
        action: RecommendedAction,
        context: ActionContext,
        incident_id: UUID | None,
        *,
        decided_by: str | None = None,
        decided_at: datetime | None = None,
    ) -> SimulatedActionResult:
        target = _username(context)
        ldap_url = (await default_secret_provider.get("AD_LDAP_URL") or "").strip()
        bind_dn = (await default_secret_provider.get("AD_BIND_DN") or "").strip()
        bind_password = await default_secret_provider.get("AD_BIND_PASSWORD") or ""
        search_base_dn = (
            await default_secret_provider.get("AD_USER_SEARCH_BASE_DN") or ""
        ).strip()
        real_execution = (
            (await default_secret_provider.get("AD_REAL_EXECUTION") or "")
            .strip()
            .casefold()
            == "true"
        )
        if ldap_url and bind_dn and bind_password and search_base_dn and real_execution:
            sam_account_name = _sam_account_name(context)
            try:
                client = ActiveDirectoryClient(
                    ldap_url, bind_dn, bind_password, search_base_dn
                )
                outcome = await client.disable_user(sam_account_name)
            except (ActiveDirectoryError, ValueError) as exc:
                raise ActionExecutionError(
                    str(exc),
                    details={
                        "integration": "active_directory",
                        "operation": "disable_account",
                        "mode": "real",
                        "error": str(exc),
                    },
                ) from exc
            state = "was already disabled" if outcome.already_disabled else "was disabled"
            return SimulatedActionResult(
                description=(
                    f"Active Directory account {target} {state} and was confirmed disabled."
                ),
                target_identifier=target,
                details={
                    "integration": "active_directory",
                    "operation": "disable_account",
                    "mode": "real",
                    "already_disabled": outcome.already_disabled,
                    "disable_confirmed": True,
                },
            )
        return _result(
            f"Would disable Active Directory account {target}.",
            target,
            integration="active_directory",
            operation="disable_account",
        )


class BlockIpHandler:
    action_type = ResponseActionType.BLOCK_IP

    async def simulate(
        self,
        action: RecommendedAction,
        context: ActionContext,
        incident_id: UUID | None,
        *,
        decided_by: str | None = None,
        decided_at: datetime | None = None,
    ) -> SimulatedActionResult:
        target = _ip_address(context)
        base_url = (await default_secret_provider.get("FMC_BASE_URL") or "").strip()
        username = (await default_secret_provider.get("FMC_USERNAME") or "").strip()
        password = await default_secret_provider.get("FMC_PASSWORD") or ""
        network_group_id = (
            await default_secret_provider.get("FMC_BLOCKLIST_NETWORK_GROUP_ID") or ""
        ).strip()
        real_execution = (
            (await default_secret_provider.get("FMC_REAL_EXECUTION") or "")
            .strip()
            .casefold()
            == "true"
        )
        if base_url and username and password and network_group_id and real_execution:
            try:
                async with FirepowerClient(base_url, username, password) as client:
                    outcome = await client.add_blocklist_member(network_group_id, target)
            except (FirepowerError, ValueError) as exc:
                details: dict[str, object] = {
                    "integration": "cisco_fmc",
                    "operation": "add_blocklist_member",
                    "mode": "real",
                    "error": str(exc),
                }
                if isinstance(exc, FirepowerError) and exc.status_code is not None:
                    details["status_code"] = exc.status_code
                raise ActionExecutionError(str(exc), details=details) from exc
            return SimulatedActionResult(
                description=(
                    f"Cisco FMC blocklist membership confirmed for IP {target}; "
                    "deployment is required before enforcement."
                ),
                target_identifier=target,
                details={
                    "integration": "cisco_fmc",
                    "operation": "add_blocklist_member",
                    "mode": "real",
                    "already_blocked": outcome.already_blocked,
                    "membership_confirmed": True,
                    "enforcement_pending_deploy": outcome.enforcement_pending_deploy,
                },
            )
        return _result(
            f"Would add IP {target} to the firewall deny policy.",
            target,
            integration="cisco_fmc",
            operation="add_blocklist_member",
        )


class CloseSessionHandler:
    action_type = ResponseActionType.CLOSE_SESSION

    async def simulate(
        self,
        action: RecommendedAction,
        context: ActionContext,
        incident_id: UUID | None,
        *,
        decided_by: str | None = None,
        decided_at: datetime | None = None,
    ) -> SimulatedActionResult:
        if context.session_id is None:
            raise SimulationTargetError("JumpServer session identifier is missing")
        base_url = (await default_secret_provider.get("JUMPSERVER_BASE_URL") or "").strip()
        api_token = (await default_secret_provider.get("JUMPSERVER_API_TOKEN") or "").strip()
        real_execution = (
            (await default_secret_provider.get("JUMPSERVER_REAL_EXECUTION") or "")
            .strip()
            .casefold()
            == "true"
        )
        if base_url and api_token and real_execution:
            try:
                async with JumpServerClient(base_url, api_token) as client:
                    outcome = await client.terminate_session(context.session_id)
            except (JumpServerError, ValueError) as exc:
                details: dict[str, object] = {
                    "integration": "jumpserver",
                    "operation": "terminate_session",
                    "mode": "real",
                    "error": str(exc),
                }
                if isinstance(exc, JumpServerError) and exc.status_code is not None:
                    details["status_code"] = exc.status_code
                raise ActionExecutionError(str(exc), details=details) from exc
            return SimulatedActionResult(
                description=(
                    f"JumpServer session {context.session_id} was confirmed terminated."
                ),
                target_identifier=context.session_id,
                details={
                    "integration": "jumpserver",
                    "operation": "terminate_session",
                    "mode": "real",
                    "termination_confirmed": outcome.termination_confirmed,
                    "is_finished": True,
                },
            )
        return _result(
            f"Would terminate JumpServer session {context.session_id}.",
            context.session_id,
            integration="jumpserver",
            operation="terminate_session",
        )


class RequireMfaHandler:
    action_type = ResponseActionType.REQUIRE_MFA

    async def simulate(
        self,
        action: RecommendedAction,
        context: ActionContext,
        incident_id: UUID | None,
        *,
        decided_by: str | None = None,
        decided_at: datetime | None = None,
    ) -> SimulatedActionResult:
        target = _username(context)
        api_hostname = (await default_secret_provider.get("DUO_API_HOSTNAME") or "").strip()
        integration_key = (
            await default_secret_provider.get("DUO_INTEGRATION_KEY") or ""
        ).strip()
        secret_key = await default_secret_provider.get("DUO_SECRET_KEY") or ""
        real_execution = (
            (await default_secret_provider.get("DUO_REAL_EXECUTION") or "")
            .strip()
            .casefold()
            == "true"
        )
        if api_hostname and integration_key and secret_key and real_execution:
            username = _sam_account_name(context)
            try:
                async with DuoClient(api_hostname, integration_key, secret_key) as client:
                    outcome = await client.require_verification(username)
            except (DuoError, ValueError) as exc:
                details: dict[str, object] = {
                    "integration": "duo",
                    "operation": "send_verification_push",
                    "mode": "real",
                    "error": str(exc),
                }
                if isinstance(exc, DuoError) and exc.status_code is not None:
                    details["status_code"] = exc.status_code
                raise ActionExecutionError(str(exc), details=details) from exc
            return SimulatedActionResult(
                description=f"Duo verification push was approved for account {target}.",
                target_identifier=target,
                details={
                    "integration": "duo",
                    "operation": "send_verification_push",
                    "mode": "real",
                    "verification_confirmed": outcome.verification_confirmed,
                },
            )
        return _result(
            f"Would require an MFA challenge for account {target} on its next access.",
            target,
            integration="duo",
            operation="send_verification_push",
        )


class NotifyAdministratorHandler:
    action_type = ResponseActionType.NOTIFY_ADMINISTRATOR

    async def simulate(
        self,
        action: RecommendedAction,
        context: ActionContext,
        incident_id: UUID | None,
        *,
        decided_by: str | None = None,
        decided_at: datetime | None = None,
    ) -> SimulatedActionResult:
        target = str(incident_id) if incident_id is not None else "unlinked response request"
        webhook_url = (await default_secret_provider.get("NOTIFY_WEBHOOK_URL") or "").strip()
        real_execution = (
            (await default_secret_provider.get("NOTIFY_REAL_EXECUTION") or "")
            .strip()
            .casefold()
            == "true"
        )
        if webhook_url and real_execution:
            try:
                async with WebhookClient(webhook_url) as client:
                    status_code = await client.send_notification(
                        incident_id,
                        context.severity or "unknown",
                        action.rationale,
                        datetime.now(UTC),
                    )
            except WebhookError as exc:
                details: dict[str, object] = {
                    "integration": "webhook",
                    "operation": "send_webhook_notification",
                    "mode": "real",
                    "error": str(exc),
                }
                if isinstance(exc, WebhookError) and exc.status_code is not None:
                    details["status_code"] = exc.status_code
                raise ActionExecutionError(str(exc), details=details) from exc
            return SimulatedActionResult(
                description=f"Administrator webhook notification sent for {target}.",
                target_identifier=target,
                details={
                    "integration": "webhook",
                    "operation": "send_webhook_notification",
                    "mode": "real",
                    "status_code": status_code,
                },
            )
        return _result(
            f"Would log an administrator notification for {target}.",
            target,
            integration="webhook",
            operation="send_webhook_notification",
        )


class CreateIncidentHandler:
    action_type = ResponseActionType.CREATE_INCIDENT

    async def simulate(
        self,
        action: RecommendedAction,
        context: ActionContext,
        incident_id: UUID | None,
        *,
        decided_by: str | None = None,
        decided_at: datetime | None = None,
    ) -> SimulatedActionResult:
        target = str(incident_id) if incident_id is not None else "new response tracking record"
        webhook_url = (
            await default_secret_provider.get("TICKETING_WEBHOOK_URL") or ""
        ).strip()
        real_execution = (
            (await default_secret_provider.get("TICKETING_REAL_EXECUTION") or "")
            .strip()
            .casefold()
            == "true"
        )
        if webhook_url and real_execution:
            title = (
                f"WardHound incident {incident_id}"
                if incident_id is not None
                else "WardHound unlinked response"
            )
            try:
                async with TicketingClient(webhook_url) as client:
                    outcome = await client.create_ticket(
                        title,
                        action.rationale,
                        incident_id,
                        context.severity or "unknown",
                    )
            except TicketingError as exc:
                details: dict[str, object] = {
                    "integration": "ticketing",
                    "operation": "create_ticket",
                    "mode": "real",
                    "error": str(exc),
                }
                if exc.status_code is not None:
                    details["status_code"] = exc.status_code
                raise ActionExecutionError(str(exc), details=details) from exc
            return SimulatedActionResult(
                description=(
                    f"External tracking ticket {outcome.ticket_id} was created for {target}."
                ),
                target_identifier=target,
                details={
                    "integration": "ticketing",
                    "operation": "create_ticket",
                    "mode": "real",
                    "status_code": outcome.status_code,
                    "ticket_id": outcome.ticket_id,
                },
            )
        return _result(
            f"Would open a simulated incident tracking record linked to {target}.",
            target,
            integration="ticketing",
            operation="create_ticket",
        )


class RequireManualApprovalHandler:
    action_type = ResponseActionType.REQUIRE_MANUAL_APPROVAL

    async def simulate(
        self,
        action: RecommendedAction,
        context: ActionContext,
        incident_id: UUID | None,
        *,
        decided_by: str | None = None,
        decided_at: datetime | None = None,
    ) -> SimulatedActionResult:
        target = str(incident_id) if incident_id is not None else "unlinked response request"
        if decided_by is None or decided_at is None:
            raise SimulationTargetError("manual approval decision metadata is missing")
        return SimulatedActionResult(
            description=(
                f"Manual approval checkpoint satisfied by {decided_by} at {decided_at}."
            ),
            target_identifier=target,
            details={
                "integration": "approval_audit",
                "operation": "record_manual_checkpoint",
                "mode": "real",
            },
        )


DEFAULT_HANDLERS: tuple[SimulatedActionHandler, ...] = (
    QuarantineDeviceHandler(),
    DisableUserHandler(),
    BlockIpHandler(),
    CloseSessionHandler(),
    RequireMfaHandler(),
    NotifyAdministratorHandler(),
    CreateIncidentHandler(),
    RequireManualApprovalHandler(),
)


class ResponseEngine:
    """Persist approval decisions and invoke safe-by-default handlers."""

    def __init__(
        self,
        store: ApprovalStore,
        handlers: Iterable[SimulatedActionHandler] | None = None,
    ) -> None:
        registered = tuple(handlers) if handlers is not None else DEFAULT_HANDLERS
        self.store = store
        self.handlers = {handler.action_type: handler for handler in registered}
        if len(self.handlers) != len(registered):
            raise ValueError("Only one simulated handler may be registered per action type")

    async def request_action(
        self,
        action: RecommendedAction,
        incident_id: UUID | None = None,
        context: ActionContext | None = None,
    ) -> ActionAuditRecord:
        """Create a request, enforcing the privileged gate before any simulation."""
        privileged = action.action_type in RecommendedAction.PRIVILEGED_ACTIONS
        if privileged and not action.requires_approval:
            action = RecommendedAction(
                action_type=action.action_type,
                rationale=action.rationale,
                requires_approval=True,
            )
        needs_approval = privileged or action.requires_approval
        record = ActionAuditRecord(
            action=action,
            incident_id=incident_id,
            context=context or ActionContext(),
            approval_status=(
                ApprovalStatus.PENDING if needs_approval else ApprovalStatus.AUTO_APPROVED
            ),
        )
        await self.store.append(record)
        return record if needs_approval else await self._execute(record)

    async def list_for_incident(self, incident_id: UUID) -> list[ActionAuditRecord]:
        """Return current response records associated with an incident."""
        return await self.store.list_for_incident(incident_id)

    async def approve(self, record_id: UUID, decided_by: str) -> ActionAuditRecord:
        """Approve a pending request and then run its simulated handler."""
        record = await self._pending_record(record_id)
        approved = record.model_copy(
            update={
                "approval_status": ApprovalStatus.APPROVED,
                "decided_by": _required_text(decided_by, "decided_by"),
                "decided_at": datetime.now(UTC),
            }
        )
        await self.store.append(approved)
        return await self._execute(approved)

    async def reject(
        self, record_id: UUID, decided_by: str, reason: str
    ) -> ActionAuditRecord:
        """Reject a pending request without invoking any handler."""
        record = await self._pending_record(record_id)
        rejected = record.model_copy(
            update={
                "approval_status": ApprovalStatus.REJECTED,
                "decided_by": _required_text(decided_by, "decided_by"),
                "decided_at": datetime.now(UTC),
                "reason": _required_text(reason, "reason"),
            }
        )
        await self.store.append(rejected)
        return rejected

    async def _pending_record(self, record_id: UUID) -> ActionAuditRecord:
        record = await self.store.get(record_id)
        if record is None:
            raise ActionRecordNotFoundError(f"Unknown response record: {record_id}")
        if record.approval_status is not ApprovalStatus.PENDING:
            raise InvalidActionTransitionError(
                f"Response record {record_id} is {record.approval_status}, not pending"
            )
        return record

    async def _execute(self, record: ActionAuditRecord) -> ActionAuditRecord:
        handler = self.handlers.get(record.action.action_type)
        if handler is None:
            result = SimulatedActionResult(
                description="Simulation failed because no handler was registered.",
                details={"error": "missing_handler"},
            )
            executed = record.model_copy(
                update={"execution_status": ExecutionStatus.FAILED, "result": result}
            )
        else:
            try:
                result = await handler.simulate(
                    record.action,
                    record.context,
                    record.incident_id,
                    decided_by=record.decided_by,
                    decided_at=record.decided_at,
                )
            except SimulationTargetError as exc:
                result = SimulatedActionResult(
                    description=f"Simulation failed: {exc}.",
                    details={"error": str(exc)},
                )
                executed = record.model_copy(
                    update={"execution_status": ExecutionStatus.FAILED, "result": result}
                )
            except ActionExecutionError as exc:
                result = SimulatedActionResult(
                    description=f"Real execution failed: {exc}.",
                    details=exc.details,
                )
                executed = record.model_copy(
                    update={"execution_status": ExecutionStatus.FAILED, "result": result}
                )
            else:
                executed = record.model_copy(
                    update={"execution_status": ExecutionStatus.SIMULATED, "result": result}
                )
        await self.store.append(executed)
        return executed


def action_context_from_incident(
    incident: Incident, evidence: Sequence[NormalizedEvent] = ()
) -> ActionContext:
    """Snapshot incident entities and a JumpServer session ID from its evidence.

    The JumpServer collector (app/collectors/jumpserver.py) does not emit a "session_id"
    key: session-lifecycle events store the JumpServer session UUID under "id"
    (JumpServerCollector._normalize_session), while command/anomaly events store it under
    "session" (JumpServerCollector._normalize_command). Both are checked here, "session"
    first since a command-triggered anomaly is the more common CLOSE_SESSION trigger.
    """
    incident_event_ids = frozenset(incident.event_ids)
    session_id: str | None = None
    for event in evidence:
        if event.id not in incident_event_ids:
            continue
        if event.source_system is not SourceSystem.JUMPSERVER:
            continue
        for key in ("session", "id"):
            candidate = event.extra_attributes.get(key)
            if isinstance(candidate, str) and candidate.strip():
                session_id = candidate.strip()
                break
        if session_id:
            break
    return ActionContext(
        entities=tuple(incident.entities),
        session_id=session_id,
        severity=incident.severity.value,
    )


def _device_mac(context: ActionContext) -> str:
    for entity in context.entities:
        if entity.entity_type is EntityType.DEVICE and entity.mac_address:
            return entity.mac_address.upper()
    raise SimulationTargetError("device MAC address is missing")


def _username(context: ActionContext) -> str:
    for entity in context.entities:
        if entity.entity_type is EntityType.USER and entity.username:
            return entity.display_name
    raise SimulationTargetError("user identifier is missing")


def _sam_account_name(context: ActionContext) -> str:
    for entity in context.entities:
        if entity.entity_type is EntityType.USER and entity.username:
            return entity.username
    raise SimulationTargetError("user identifier is missing")


def _ip_address(context: ActionContext) -> str:
    for entity in context.entities:
        if entity.ip_address:
            return entity.ip_address
    raise SimulationTargetError("IP address is missing")


def _result(
    description: str, target: str, *, integration: str, operation: str
) -> SimulatedActionResult:
    return SimulatedActionResult(
        description=description,
        target_identifier=target,
        details={"integration": integration, "operation": operation, "mode": "simulation"},
    )


def _required_text(value: str, field_name: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field_name} must not be empty")
    return normalized
