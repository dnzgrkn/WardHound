"""HTTP and WebSocket contracts for the dashboard API."""

from __future__ import annotations

from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

from app.schemas.analysis import RootCauseAnalysis
from app.schemas.events import NormalizedEvent
from app.schemas.incidents import Incident


class EventBatch(BaseModel):
    """Already-normalized events submitted for deterministic pipeline processing."""

    events: list[NormalizedEvent] = Field(min_length=1)


class IncidentDetail(BaseModel):
    """One incident with retained evidence and an optional on-demand analysis."""

    incident: Incident
    evidence: list[NormalizedEvent]
    analysis: RootCauseAnalysis | None = None


class AnalysisCompleted(BaseModel):
    """Realtime payload emitted after an incident analysis is retained."""

    incident_id: UUID
    analysis: RootCauseAnalysis


class IncidentSortField(StrEnum):
    """Explicit incident sort keys supported by the list endpoint."""

    CREATED_AT = "created_at"
    RISK_SCORE = "risk_score"


class SortOrder(StrEnum):
    """Supported list sort directions."""

    ASC = "asc"
    DESC = "desc"


class ApprovalDecision(BaseModel):
    """Operator identifier supplied when approving a response action."""

    decided_by: str = Field(min_length=1)

    @field_validator("decided_by")
    @classmethod
    def normalize_decided_by(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("decided_by must not be empty")
        return normalized


class RejectionDecision(ApprovalDecision):
    """Operator identifier and rationale supplied when rejecting an action."""

    reason: str = Field(min_length=1)

    @field_validator("reason")
    @classmethod
    def normalize_reason(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("reason must not be empty")
        return normalized


class ApiError(BaseModel):
    """Stable error payload returned for known service-layer failures."""

    code: str
    message: str


class RealtimeEventType(StrEnum):
    """Closed WebSocket update vocabulary consumed by the dashboard."""

    INCIDENT_CREATED = "incident_created"
    INCIDENT_UPDATED = "incident_updated"
    ANALYSIS_COMPLETED = "analysis_completed"
    ACTION_UPDATED = "action_updated"


class RealtimeMessage[PayloadT](BaseModel):
    """Typed realtime envelope carrying one dashboard update payload."""

    type: RealtimeEventType
    payload: PayloadT
