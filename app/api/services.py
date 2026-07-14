"""FastAPI-injected service container for the incident dashboard API."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Annotated, Protocol

from fastapi import Depends
from starlette.requests import HTTPConnection

from app.api.realtime import IncidentConnectionManager
from app.engines.response import ResponseEngine
from app.schemas.analysis import RootCauseAnalysis
from app.schemas.events import NormalizedEvent
from app.schemas.incidents import Incident
from app.stores.incidents import EventStore, IncidentStore


class AnalysisEngine(Protocol):
    """Async analysis behavior required by the on-demand endpoint."""

    async def analyze(
        self, incident: Incident, evidence: Sequence[NormalizedEvent]
    ) -> RootCauseAnalysis:
        """Return one structured analysis for retained incident evidence."""
        ...


AnalysisEngineFactory = Callable[[], AnalysisEngine]


@dataclass(frozen=True, slots=True)
class ApiServices:
    """Long-lived store ports and engine adapters used by dashboard routes."""

    incidents: IncidentStore
    events: EventStore
    response_engine: ResponseEngine
    analysis_engine_factory: AnalysisEngineFactory
    connections: IncidentConnectionManager


def get_api_services(connection: HTTPConnection) -> ApiServices:
    """Return dashboard services initialized during application lifespan."""
    services: ApiServices = connection.app.state.api_services
    return services


ApiServicesDependency = Annotated[ApiServices, Depends(get_api_services)]
