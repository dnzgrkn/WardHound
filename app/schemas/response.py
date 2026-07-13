"""Immutable response-workflow and simulated-execution contracts."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from app.schemas.analysis import RecommendedAction
from app.schemas.events import NormalizedEntity


class ApprovalStatus(StrEnum):
    """Human approval state for a recommended response action."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    AUTO_APPROVED = "auto_approved"


class ExecutionStatus(StrEnum):
    """Outcome of simulated execution; no value represents a real side effect."""

    NOT_EXECUTED = "not_executed"
    SIMULATED = "simulated"
    FAILED = "failed"


class ActionContext(BaseModel):
    """Persisted target snapshot needed by a handler after a later approval decision."""

    model_config = {"frozen": True}

    entities: tuple[NormalizedEntity, ...] = ()
    session_id: str | None = Field(default=None, min_length=1)


class SimulatedActionResult(BaseModel):
    """Auditable description of what a future real integration would have attempted."""

    model_config = {"frozen": True}

    description: str = Field(min_length=1)
    target_identifier: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class ActionAuditRecord(BaseModel):
    """One immutable snapshot in the lifecycle of a response request."""

    model_config = {"frozen": True}

    id: UUID = Field(default_factory=uuid4)
    action: RecommendedAction
    incident_id: UUID | None = None
    context: ActionContext = Field(default_factory=ActionContext)
    approval_status: ApprovalStatus
    decided_by: str | None = None
    decided_at: datetime | None = None
    reason: str | None = None
    execution_status: ExecutionStatus = ExecutionStatus.NOT_EXECUTED
    result: SimulatedActionResult | None = None
    requested_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
