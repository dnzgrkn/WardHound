"""Structured AI analysis and response-recommendation contracts."""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar
from uuid import UUID

from pydantic import BaseModel, Field, model_validator


class ResponseActionType(StrEnum):
    """Closed action vocabulary shared with the future response engine."""

    QUARANTINE_DEVICE = "quarantine_device"
    DISABLE_USER = "disable_user"
    BLOCK_IP = "block_ip"
    CLOSE_SESSION = "close_session"
    REQUIRE_MFA = "require_mfa"
    NOTIFY_ADMINISTRATOR = "notify_administrator"
    CREATE_INCIDENT = "create_incident"
    REQUIRE_MANUAL_APPROVAL = "require_manual_approval"


class Evidence(BaseModel):
    """A concise analytical claim tied to one immutable normalized event."""

    model_config = {"frozen": True}

    event_id: UUID
    description: str = Field(min_length=1)


class RecommendedAction(BaseModel):
    """
    A typed remediation recommendation, never an executable command.

    The model supplies ``requires_approval`` so operators can see the intended control, while the
    validator enforces approval for every action that changes external security state.
    """

    model_config = {"frozen": True}

    PRIVILEGED_ACTIONS: ClassVar[frozenset[ResponseActionType]] = frozenset(
        {
            ResponseActionType.QUARANTINE_DEVICE,
            ResponseActionType.DISABLE_USER,
            ResponseActionType.BLOCK_IP,
            ResponseActionType.CLOSE_SESSION,
            ResponseActionType.REQUIRE_MFA,
            ResponseActionType.REQUIRE_MANUAL_APPROVAL,
        }
    )

    action_type: ResponseActionType
    rationale: str = Field(min_length=1)
    requires_approval: bool

    @model_validator(mode="after")
    def require_approval_for_privileged_action(self) -> RecommendedAction:
        if self.action_type in self.PRIVILEGED_ACTIONS and not self.requires_approval:
            raise ValueError("Privileged response actions must require approval")
        return self


class RootCauseAnalysis(BaseModel):
    """Instructor-enforced root-cause output with cited evidence and bounded confidence."""

    model_config = {"frozen": True}

    probable_cause: str = Field(min_length=1)
    confidence: float = Field(ge=0, le=1)
    evidence: list[Evidence] = Field(min_length=1)
    recommended_actions: list[RecommendedAction]
    side_effects: str = Field(min_length=1)
