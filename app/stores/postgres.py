"""PostgreSQL-backed implementations of WardHound's async store ports."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from app.db.models import (
    DailyDigestRecord,
    IncidentRecord,
    NormalizedEventRecord,
    ResponseActionAuditRecord,
)
from app.schemas.analysis import RootCauseAnalysis
from app.schemas.digest import DailyDigest
from app.schemas.events import NormalizedEvent
from app.schemas.incidents import Incident
from app.schemas.response import ActionAuditRecord


class _PostgresStore:
    def __init__(self, engine: AsyncEngine) -> None:
        self._sessions = async_sessionmaker(engine, expire_on_commit=False)


class PostgresEventStore(_PostgresStore):
    """Persist immutable normalized event evidence by UUID."""

    async def add_all(self, events: Iterable[NormalizedEvent]) -> None:
        event_list = tuple(events)
        if not event_list:
            return

        async with self._sessions() as session:
            values = [
                {
                    "id": event.id,
                    "payload": event.model_dump(mode="json"),
                    "occurred_at": event.occurred_at,
                }
                for event in event_list
            ]
            statement = insert(NormalizedEventRecord).values(values)
            statement = statement.on_conflict_do_update(
                index_elements=[NormalizedEventRecord.id],
                set_={
                    "payload": statement.excluded.payload,
                    "occurred_at": statement.excluded.occurred_at,
                },
            )
            await session.execute(statement)
            await session.commit()

    async def get_many(self, event_ids: Sequence[UUID]) -> list[NormalizedEvent]:
        requested = tuple(event_ids)
        if not requested:
            return []

        async with self._sessions() as session:
            result = await session.execute(
                select(NormalizedEventRecord).where(NormalizedEventRecord.id.in_(requested))
            )
            by_id = {
                row.id: NormalizedEvent.model_validate(row.payload) for row in result.scalars()
            }
        return [by_id[event_id] for event_id in requested if event_id in by_id]

    async def get_all(self) -> list[NormalizedEvent]:
        async with self._sessions() as session:
            result = await session.execute(
                select(NormalizedEventRecord).order_by(
                    NormalizedEventRecord.occurred_at, NormalizedEventRecord.id
                )
            )
        return [NormalizedEvent.model_validate(row.payload) for row in result.scalars()]


class PostgresIncidentStore(_PostgresStore):
    """Persist incidents and their latest structured analysis."""

    async def upsert(self, incident: Incident) -> bool:
        async with self._sessions() as session:
            statement = insert(IncidentRecord).values(
                id=incident.id,
                payload=incident.model_dump(mode="json"),
                created_at=incident.created_at,
            )
            inserted_id = (
                await session.execute(
                    statement.on_conflict_do_nothing(
                        index_elements=[IncidentRecord.id]
                    ).returning(IncidentRecord.id)
                )
            ).scalar_one_or_none()
            if inserted_id is None:
                update_statement = statement.on_conflict_do_update(
                    index_elements=[IncidentRecord.id],
                    set_={
                        "payload": statement.excluded.payload,
                        "created_at": statement.excluded.created_at,
                    },
                )
                await session.execute(update_statement)
            await session.commit()
        return inserted_id is not None

    async def get(self, incident_id: UUID) -> Incident | None:
        async with self._sessions() as session:
            row = await session.get(IncidentRecord, incident_id)
        return Incident.model_validate(row.payload) if row is not None else None

    async def list_all(self) -> list[Incident]:
        async with self._sessions() as session:
            result = await session.execute(
                select(IncidentRecord).order_by(IncidentRecord.created_at, IncidentRecord.id)
            )
        return [Incident.model_validate(row.payload) for row in result.scalars()]

    async def save_analysis(self, incident_id: UUID, analysis: RootCauseAnalysis) -> None:
        async with self._sessions() as session:
            row = await session.get(IncidentRecord, incident_id)
            if row is None:
                raise KeyError(f"Unknown incident: {incident_id}")
            row.analysis = analysis.model_dump(mode="json")
            await session.commit()

    async def get_analysis(self, incident_id: UUID) -> RootCauseAnalysis | None:
        async with self._sessions() as session:
            row = await session.get(IncidentRecord, incident_id)
            if row is None or row.analysis is None:
                return None
        return RootCauseAnalysis.model_validate(row.analysis)


class PostgresDigestStore(_PostgresStore):
    """Persist immutable generated daily digest records by UUID."""

    async def append(self, digest: DailyDigest) -> None:
        async with self._sessions() as session:
            statement = insert(DailyDigestRecord).values(
                id=digest.id,
                payload=digest.model_dump(mode="json"),
                generated_at=digest.generated_at,
            )
            statement = statement.on_conflict_do_update(
                index_elements=[DailyDigestRecord.id],
                set_={
                    "payload": statement.excluded.payload,
                    "generated_at": statement.excluded.generated_at,
                },
            )
            await session.execute(statement)
            await session.commit()

    async def get(self, digest_id: UUID) -> DailyDigest | None:
        async with self._sessions() as session:
            row = await session.get(DailyDigestRecord, digest_id)
        return DailyDigest.model_validate(row.payload) if row is not None else None

    async def list_recent(self, limit: int) -> list[DailyDigest]:
        if limit <= 0:
            return []
        async with self._sessions() as session:
            result = await session.execute(
                select(DailyDigestRecord)
                .order_by(DailyDigestRecord.generated_at.desc(), DailyDigestRecord.id.desc())
                .limit(limit)
            )
        return [DailyDigest.model_validate(row.payload) for row in result.scalars()]


class PostgresApprovalStore(_PostgresStore):
    """Append and recover immutable response lifecycle snapshots."""

    async def append(self, record: ActionAuditRecord) -> None:
        async with self._sessions() as session:
            session.add(
                ResponseActionAuditRecord(
                    record_id=record.id,
                    incident_id=record.incident_id,
                    payload=record.model_dump(mode="json"),
                )
            )
            await session.commit()

    async def get(self, record_id: UUID) -> ActionAuditRecord | None:
        async with self._sessions() as session:
            result = await session.execute(
                select(ResponseActionAuditRecord)
                .where(ResponseActionAuditRecord.record_id == record_id)
                .order_by(ResponseActionAuditRecord.sequence_id.desc())
                .limit(1)
            )
            row = result.scalar_one_or_none()
        return ActionAuditRecord.model_validate(row.payload) if row is not None else None

    async def history(self, record_id: UUID) -> tuple[ActionAuditRecord, ...]:
        async with self._sessions() as session:
            result = await session.execute(
                select(ResponseActionAuditRecord)
                .where(ResponseActionAuditRecord.record_id == record_id)
                .order_by(ResponseActionAuditRecord.sequence_id)
            )
        return tuple(ActionAuditRecord.model_validate(row.payload) for row in result.scalars())

    async def list_for_incident(self, incident_id: UUID) -> list[ActionAuditRecord]:
        async with self._sessions() as session:
            latest = (
                select(
                    ResponseActionAuditRecord.record_id,
                    func.max(ResponseActionAuditRecord.sequence_id).label("sequence_id"),
                )
                .where(ResponseActionAuditRecord.incident_id == incident_id)
                .group_by(ResponseActionAuditRecord.record_id)
                .subquery()
            )
            result = await session.execute(
                select(ResponseActionAuditRecord)
                .join(latest, ResponseActionAuditRecord.sequence_id == latest.c.sequence_id)
                .order_by(ResponseActionAuditRecord.sequence_id)
            )
        return [ActionAuditRecord.model_validate(row.payload) for row in result.scalars()]
