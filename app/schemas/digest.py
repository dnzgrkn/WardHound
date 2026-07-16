"""Persisted daily security digest contracts."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, model_validator

from app.schemas.incidents import Incident


class AggregateStat(BaseModel):
    """One deterministic count, optionally attached to a ranked entity."""

    model_config = {"frozen": True}

    name: str = Field(min_length=1)
    label: str = Field(min_length=1)
    count: int = Field(ge=0)
    entity: str | None = Field(default=None, min_length=1)
    rank: int | None = Field(default=None, ge=1)


class DigestNarrative(BaseModel):
    """Instructor-enforced executive interpretation of deterministic digest facts."""

    model_config = {"frozen": True}

    executive_summary: str = Field(min_length=1, max_length=2000)
    highlights: list[Annotated[str, Field(min_length=1)]] = Field(max_length=10)
    recommended_follow_up: list[Annotated[str, Field(min_length=1)]] = Field(max_length=10)


class DailyDigest(BaseModel):
    """A bounded, delivery-ready record for one security activity window."""

    model_config = {"frozen": True}

    id: UUID = Field(default_factory=uuid4)
    period_start: datetime
    period_end: datetime
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    incidents: list[Incident]
    aggregate_stats: list[AggregateStat]
    narrative: DigestNarrative | None = None

    @model_validator(mode="after")
    def validate_period(self) -> DailyDigest:
        if self.period_start.tzinfo is None or self.period_end.tzinfo is None:
            raise ValueError("Digest period timestamps must be timezone-aware")
        if self.period_start >= self.period_end:
            raise ValueError("Digest period_start must be before period_end")
        return self
