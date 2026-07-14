"""Create persistent event, incident, analysis, and response audit storage.

Revision ID: 0001
Revises:
Create Date: 2026-07-14
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "normalized_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "stored_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_normalized_events_occurred_at"),
        "normalized_events",
        ["occurred_at"],
    )
    op.create_table(
        "incidents",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("analysis", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "stored_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_incidents_created_at"), "incidents", ["created_at"])
    op.create_table(
        "response_action_audit_records",
        sa.Column("sequence_id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("record_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("incident_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "appended_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("sequence_id"),
    )
    op.create_index(
        "ix_response_action_audit_incident_latest",
        "response_action_audit_records",
        ["incident_id", "record_id", "sequence_id"],
    )
    op.create_index(
        "ix_response_action_audit_record_latest",
        "response_action_audit_records",
        ["record_id", "sequence_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_response_action_audit_record_latest",
        table_name="response_action_audit_records",
    )
    op.drop_index(
        "ix_response_action_audit_incident_latest",
        table_name="response_action_audit_records",
    )
    op.drop_table("response_action_audit_records")
    op.drop_index(op.f("ix_incidents_created_at"), table_name="incidents")
    op.drop_table("incidents")
    op.drop_index(op.f("ix_normalized_events_occurred_at"), table_name="normalized_events")
    op.drop_table("normalized_events")
