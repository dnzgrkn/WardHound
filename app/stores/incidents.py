"""In-memory persistence seams for dashboard incidents and evidence."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Protocol
from uuid import UUID

from app.schemas.analysis import RootCauseAnalysis
from app.schemas.events import NormalizedEvent
from app.schemas.incidents import Incident


class EventStore(Protocol):
    """Persistence port for immutable normalized event evidence."""

    def add_all(self, events: Iterable[NormalizedEvent]) -> None:
        """Retain events by UUID, replacing only identical logical keys."""
        ...

    def get_many(self, event_ids: Sequence[UUID]) -> list[NormalizedEvent]:
        """Return available events in the requested UUID order."""
        ...


class IncidentStore(Protocol):
    """Persistence port for incidents and their optional AI analyses."""

    def upsert(self, incident: Incident) -> bool:
        """Store an incident and return true when its UUID was newly created."""
        ...

    def get(self, incident_id: UUID) -> Incident | None:
        """Return one incident by UUID."""
        ...

    def list_all(self) -> list[Incident]:
        """Return all retained incidents."""
        ...

    def save_analysis(self, incident_id: UUID, analysis: RootCauseAnalysis) -> None:
        """Associate the latest structured analysis with an incident UUID."""
        ...

    def get_analysis(self, incident_id: UUID) -> RootCauseAnalysis | None:
        """Return the latest structured analysis for an incident UUID."""
        ...


class InMemoryEventStore:
    """Dict-backed event store for local dashboard use and tests."""

    def __init__(self) -> None:
        self._events: dict[UUID, NormalizedEvent] = {}

    def add_all(self, events: Iterable[NormalizedEvent]) -> None:
        self._events.update((event.id, event) for event in events)

    def get_many(self, event_ids: Sequence[UUID]) -> list[NormalizedEvent]:
        return [self._events[event_id] for event_id in event_ids if event_id in self._events]


class InMemoryIncidentStore:
    """Dict-backed incident and analysis store for local dashboard use and tests."""

    def __init__(self) -> None:
        self._incidents: dict[UUID, Incident] = {}
        self._analyses: dict[UUID, RootCauseAnalysis] = {}

    def upsert(self, incident: Incident) -> bool:
        created = incident.id not in self._incidents
        self._incidents[incident.id] = incident
        return created

    def get(self, incident_id: UUID) -> Incident | None:
        return self._incidents.get(incident_id)

    def list_all(self) -> list[Incident]:
        return list(self._incidents.values())

    def save_analysis(self, incident_id: UUID, analysis: RootCauseAnalysis) -> None:
        if incident_id not in self._incidents:
            raise KeyError(f"Unknown incident: {incident_id}")
        self._analyses[incident_id] = analysis

    def get_analysis(self, incident_id: UUID) -> RootCauseAnalysis | None:
        return self._analyses.get(incident_id)
