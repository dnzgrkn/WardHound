"""SQLAlchemy models for durable WardHound application state."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import BigInteger, DateTime, Index, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PostgresUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Declarative metadata root used by Alembic."""


class NormalizedEventRecord(Base):
    """Durable normalized event stored as its canonical Pydantic JSON payload."""

    __tablename__ = "normalized_events"

    id: Mapped[UUID] = mapped_column(PostgresUUID(as_uuid=True), primary_key=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    stored_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class IncidentRecord(Base):
    """Durable incident and its optional latest root-cause analysis."""

    __tablename__ = "incidents"

    id: Mapped[UUID] = mapped_column(PostgresUUID(as_uuid=True), primary_key=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB)
    analysis: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    stored_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class ResponseActionAuditRecord(Base):
    """Append-only response action lifecycle snapshot."""

    __tablename__ = "response_action_audit_records"
    __table_args__ = (
        Index(
            "ix_response_action_audit_record_latest",
            "record_id",
            "sequence_id",
        ),
        Index(
            "ix_response_action_audit_incident_latest",
            "incident_id",
            "record_id",
            "sequence_id",
        ),
    )

    sequence_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    record_id: Mapped[UUID] = mapped_column(PostgresUUID(as_uuid=True), nullable=False)
    incident_id: Mapped[UUID | None] = mapped_column(
        PostgresUUID(as_uuid=True), nullable=True
    )
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB)
    appended_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
