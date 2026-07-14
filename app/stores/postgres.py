"""PostgreSQL-backed implementations of WardHound's synchronous store ports."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.db.models import IncidentRecord, NormalizedEventRecord, ResponseActionAuditRecord
from app.schemas.analysis import RootCauseAnalysis
from app.schemas.events import NormalizedEvent
from app.schemas.incidents import Incident
from app.schemas.response import ActionAuditRecord


def _run_sync[T](operation: Callable[[], Coroutine[Any, Any, T]]) -> T:
    """Run async database work behind the pre-existing synchronous store ports."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(operation())

    def run_operation() -> T:
        return asyncio.run(operation())

    with ThreadPoolExecutor(max_workers=1) as executor:
        return executor.submit(run_operation).result()


class _PostgresStore:
    def __init__(self, engine: AsyncEngine) -> None:
        self._sessions = async_sessionmaker(engine, expire_on_commit=False)

    def _run[T](self, operation: Callable[[AsyncSession], Coroutine[Any, Any, T]]) -> T:
        async def in_session() -> T:
            async with self._sessions() as session:
                return await operation(session)

        return _run_sync(in_session)


class PostgresEventStore(_PostgresStore):
    """Persist immutable normalized event evidence by UUID."""

    def add_all(self, events: Iterable[NormalizedEvent]) -> None:
        event_list = tuple(events)
        if not event_list:
            return

        async def add(session: AsyncSession) -> None:
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

        self._run(add)

    def get_many(self, event_ids: Sequence[UUID]) -> list[NormalizedEvent]:
        requested = tuple(event_ids)
        if not requested:
            return []

        async def get(session: AsyncSession) -> list[NormalizedEvent]:
            result = await session.execute(
                select(NormalizedEventRecord).where(NormalizedEventRecord.id.in_(requested))
            )
            by_id = {
                row.id: NormalizedEvent.model_validate(row.payload) for row in result.scalars()
            }
            return [by_id[event_id] for event_id in requested if event_id in by_id]

        return self._run(get)

    def get_all(self) -> list[NormalizedEvent]:
        async def get(session: AsyncSession) -> list[NormalizedEvent]:
            result = await session.execute(
                select(NormalizedEventRecord).order_by(
                    NormalizedEventRecord.occurred_at, NormalizedEventRecord.id
                )
            )
            return [NormalizedEvent.model_validate(row.payload) for row in result.scalars()]

        return self._run(get)


class PostgresIncidentStore(_PostgresStore):
    """Persist incidents and their latest structured analysis."""

    def upsert(self, incident: Incident) -> bool:
        async def save(session: AsyncSession) -> bool:
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

        return self._run(save)

    def get(self, incident_id: UUID) -> Incident | None:
        async def get_one(session: AsyncSession) -> Incident | None:
            row = await session.get(IncidentRecord, incident_id)
            return Incident.model_validate(row.payload) if row is not None else None

        return self._run(get_one)

    def list_all(self) -> list[Incident]:
        async def get(session: AsyncSession) -> list[Incident]:
            result = await session.execute(
                select(IncidentRecord).order_by(IncidentRecord.created_at, IncidentRecord.id)
            )
            return [Incident.model_validate(row.payload) for row in result.scalars()]

        return self._run(get)

    def save_analysis(self, incident_id: UUID, analysis: RootCauseAnalysis) -> None:
        async def save(session: AsyncSession) -> None:
            row = await session.get(IncidentRecord, incident_id)
            if row is None:
                raise KeyError(f"Unknown incident: {incident_id}")
            row.analysis = analysis.model_dump(mode="json")
            await session.commit()

        self._run(save)

    def get_analysis(self, incident_id: UUID) -> RootCauseAnalysis | None:
        async def get(session: AsyncSession) -> RootCauseAnalysis | None:
            row = await session.get(IncidentRecord, incident_id)
            if row is None or row.analysis is None:
                return None
            return RootCauseAnalysis.model_validate(row.analysis)

        return self._run(get)


class PostgresApprovalStore(_PostgresStore):
    """Append and recover immutable response lifecycle snapshots."""

    def append(self, record: ActionAuditRecord) -> None:
        async def add(session: AsyncSession) -> None:
            session.add(
                ResponseActionAuditRecord(
                    record_id=record.id,
                    incident_id=record.incident_id,
                    payload=record.model_dump(mode="json"),
                )
            )
            await session.commit()

        self._run(add)

    def get(self, record_id: UUID) -> ActionAuditRecord | None:
        async def get_one(session: AsyncSession) -> ActionAuditRecord | None:
            result = await session.execute(
                select(ResponseActionAuditRecord)
                .where(ResponseActionAuditRecord.record_id == record_id)
                .order_by(ResponseActionAuditRecord.sequence_id.desc())
                .limit(1)
            )
            row = result.scalar_one_or_none()
            return ActionAuditRecord.model_validate(row.payload) if row is not None else None

        return self._run(get_one)

    def history(self, record_id: UUID) -> tuple[ActionAuditRecord, ...]:
        async def get(session: AsyncSession) -> tuple[ActionAuditRecord, ...]:
            result = await session.execute(
                select(ResponseActionAuditRecord)
                .where(ResponseActionAuditRecord.record_id == record_id)
                .order_by(ResponseActionAuditRecord.sequence_id)
            )
            return tuple(
                ActionAuditRecord.model_validate(row.payload) for row in result.scalars()
            )

        return self._run(get)

    def list_for_incident(self, incident_id: UUID) -> list[ActionAuditRecord]:
        async def get(session: AsyncSession) -> list[ActionAuditRecord]:
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

        return self._run(get)
