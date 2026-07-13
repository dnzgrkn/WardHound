"""Human-gated response workflow with simulated action handlers only."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID

from app.schemas.analysis import RecommendedAction, ResponseActionType
from app.schemas.events import EntityType, NormalizedEvent
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


class ApprovalStore(Protocol):
    """Persistence seam for immutable response lifecycle snapshots."""

    def append(self, record: ActionAuditRecord) -> None:
        """Append a new snapshot for a request without altering earlier snapshots."""
        ...

    def get(self, record_id: UUID) -> ActionAuditRecord | None:
        """Return the latest snapshot for a request, if it exists."""
        ...

    def history(self, record_id: UUID) -> tuple[ActionAuditRecord, ...]:
        """Return every snapshot for a request in append order."""
        ...


class InMemoryApprovalStore:
    """Dict-backed Stage 5 store used in tests and local simulations."""

    def __init__(self) -> None:
        self._records: dict[UUID, list[ActionAuditRecord]] = {}

    def append(self, record: ActionAuditRecord) -> None:
        self._records.setdefault(record.id, []).append(record)

    def get(self, record_id: UUID) -> ActionAuditRecord | None:
        snapshots = self._records.get(record_id)
        return snapshots[-1] if snapshots else None

    def history(self, record_id: UUID) -> tuple[ActionAuditRecord, ...]:
        return tuple(self._records.get(record_id, ()))


class SimulatedActionHandler(Protocol):
    """Extension point implemented by one simulator per response action type."""

    action_type: ResponseActionType

    def simulate(
        self,
        action: RecommendedAction,
        context: ActionContext,
        incident_id: UUID | None,
    ) -> SimulatedActionResult:
        """Describe a future integration call without performing it."""
        ...


class QuarantineDeviceHandler:
    action_type = ResponseActionType.QUARANTINE_DEVICE

    def simulate(
        self, action: RecommendedAction, context: ActionContext, incident_id: UUID | None
    ) -> SimulatedActionResult:
        target = _device_mac(context)
        return _result(
            f"Would set PacketFence node status to isolated for MAC {target}.",
            target,
            integration="packetfence",
            operation="isolate_node",
        )


class DisableUserHandler:
    action_type = ResponseActionType.DISABLE_USER

    def simulate(
        self, action: RecommendedAction, context: ActionContext, incident_id: UUID | None
    ) -> SimulatedActionResult:
        target = _username(context)
        return _result(
            f"Would disable Active Directory account {target}.",
            target,
            integration="active_directory",
            operation="disable_account",
        )


class BlockIpHandler:
    action_type = ResponseActionType.BLOCK_IP

    def simulate(
        self, action: RecommendedAction, context: ActionContext, incident_id: UUID | None
    ) -> SimulatedActionResult:
        target = _ip_address(context)
        return _result(
            f"Would add IP {target} to the firewall deny policy.",
            target,
            integration="firewall",
            operation="add_deny_rule",
        )


class CloseSessionHandler:
    action_type = ResponseActionType.CLOSE_SESSION

    def simulate(
        self, action: RecommendedAction, context: ActionContext, incident_id: UUID | None
    ) -> SimulatedActionResult:
        if context.session_id is None:
            raise SimulationTargetError("JumpServer session identifier is missing")
        return _result(
            f"Would terminate JumpServer session {context.session_id}.",
            context.session_id,
            integration="jumpserver",
            operation="terminate_session",
        )


class RequireMfaHandler:
    action_type = ResponseActionType.REQUIRE_MFA

    def simulate(
        self, action: RecommendedAction, context: ActionContext, incident_id: UUID | None
    ) -> SimulatedActionResult:
        target = _username(context)
        return _result(
            f"Would require an MFA challenge for account {target} on its next access.",
            target,
            integration="identity_provider",
            operation="require_mfa",
        )


class NotifyAdministratorHandler:
    action_type = ResponseActionType.NOTIFY_ADMINISTRATOR

    def simulate(
        self, action: RecommendedAction, context: ActionContext, incident_id: UUID | None
    ) -> SimulatedActionResult:
        target = str(incident_id) if incident_id is not None else "unlinked response request"
        return _result(
            f"Would log an administrator notification for {target}.",
            target,
            integration="notification_log",
            operation="record_notification",
        )


class CreateIncidentHandler:
    action_type = ResponseActionType.CREATE_INCIDENT

    def simulate(
        self, action: RecommendedAction, context: ActionContext, incident_id: UUID | None
    ) -> SimulatedActionResult:
        target = str(incident_id) if incident_id is not None else "new response tracking record"
        return _result(
            f"Would open a simulated incident tracking record linked to {target}.",
            target,
            integration="incident_store",
            operation="create_tracking_record",
        )


class RequireManualApprovalHandler:
    action_type = ResponseActionType.REQUIRE_MANUAL_APPROVAL

    def simulate(
        self, action: RecommendedAction, context: ActionContext, incident_id: UUID | None
    ) -> SimulatedActionResult:
        target = str(incident_id) if incident_id is not None else "unlinked response request"
        return _result(
            f"Would record a satisfied manual-approval checkpoint for {target}.",
            target,
            integration="approval_audit",
            operation="record_manual_checkpoint",
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
    """Persist approval decisions and invoke only simulated handlers."""

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

    def request_action(
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
        self.store.append(record)
        return record if needs_approval else self._execute(record)

    def approve(self, record_id: UUID, decided_by: str) -> ActionAuditRecord:
        """Approve a pending request and then run its simulated handler."""
        record = self._pending_record(record_id)
        approved = record.model_copy(
            update={
                "approval_status": ApprovalStatus.APPROVED,
                "decided_by": _required_text(decided_by, "decided_by"),
                "decided_at": datetime.now(UTC),
            }
        )
        self.store.append(approved)
        return self._execute(approved)

    def reject(self, record_id: UUID, decided_by: str, reason: str) -> ActionAuditRecord:
        """Reject a pending request without invoking any handler."""
        record = self._pending_record(record_id)
        rejected = record.model_copy(
            update={
                "approval_status": ApprovalStatus.REJECTED,
                "decided_by": _required_text(decided_by, "decided_by"),
                "decided_at": datetime.now(UTC),
                "reason": _required_text(reason, "reason"),
            }
        )
        self.store.append(rejected)
        return rejected

    def _pending_record(self, record_id: UUID) -> ActionAuditRecord:
        record = self.store.get(record_id)
        if record is None:
            raise ActionRecordNotFoundError(f"Unknown response record: {record_id}")
        if record.approval_status is not ApprovalStatus.PENDING:
            raise InvalidActionTransitionError(
                f"Response record {record_id} is {record.approval_status}, not pending"
            )
        return record

    def _execute(self, record: ActionAuditRecord) -> ActionAuditRecord:
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
                result = handler.simulate(record.action, record.context, record.incident_id)
            except SimulationTargetError as exc:
                result = SimulatedActionResult(
                    description=f"Simulation failed: {exc}.",
                    details={"error": str(exc)},
                )
                executed = record.model_copy(
                    update={"execution_status": ExecutionStatus.FAILED, "result": result}
                )
            else:
                executed = record.model_copy(
                    update={"execution_status": ExecutionStatus.SIMULATED, "result": result}
                )
        self.store.append(executed)
        return executed


def action_context_from_incident(
    incident: Incident, evidence: Sequence[NormalizedEvent] = ()
) -> ActionContext:
    """Snapshot incident entities and a JumpServer session ID from its evidence."""
    incident_event_ids = frozenset(incident.event_ids)
    session_id: str | None = None
    for event in evidence:
        if event.id not in incident_event_ids:
            continue
        candidate = event.extra_attributes.get("session_id")
        if isinstance(candidate, str) and candidate.strip():
            session_id = candidate.strip()
            break
    return ActionContext(entities=tuple(incident.entities), session_id=session_id)


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
