"""Incident and policy evidence contracts for WardHound engines."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from app.schemas.events import NormalizedEntity, Severity


class IncidentStatus(StrEnum):
    """Minimal lifecycle states needed by later incident-management stages."""

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class PolicyViolation(BaseModel):
    """A deterministic policy finding supported by normalized event evidence."""

    model_config = {"frozen": True}

    rule_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    description: str = Field(min_length=1)
    event_ids: list[UUID] = Field(min_length=1)
    entities: list[NormalizedEntity] = Field(default_factory=list)
    severity: Severity


class Incident(BaseModel):
    """
    A correlated security incident referencing immutable normalized events.

    Event IDs are stored instead of embedding full events so the incident remains a compact
    aggregate. Callers retain the event collection for scoring and evidence display until a
    persistent event repository is introduced.
    """

    model_config = {"frozen": True}

    id: UUID = Field(default_factory=uuid4)
    title: str = Field(min_length=1, max_length=200)
    summary: str = Field(min_length=1)
    event_ids: list[UUID] = Field(min_length=1)
    entities: list[NormalizedEntity] = Field(min_length=1)
    severity: Severity
    risk_score: float = Field(ge=0, le=100)
    status: IncidentStatus = IncidentStatus.OPEN
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    correlation_rule_id: str = Field(min_length=1)
    policy_violations: list[PolicyViolation] = Field(default_factory=list)
