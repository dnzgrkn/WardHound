"""REST composition layer over WardHound's existing incident engines."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from fastapi.responses import JSONResponse

from app.api.auth import require_api_key
from app.api.models import (
    ApiError,
    ApprovalDecision,
    EventBatch,
    IncidentDetail,
    IncidentSortField,
    RealtimeEventType,
    RealtimeMessage,
    RejectionDecision,
    SortOrder,
)
from app.api.services import ApiServicesDependency
from app.engines.analysis import (
    AnalysisConfigurationError,
    AnalysisGenerationError,
    AnalysisInputError,
)
from app.engines.pipeline import run_pipeline
from app.engines.response import (
    ActionRecordNotFoundError,
    InvalidActionTransitionError,
    action_context_from_incident,
)
from app.schemas.analysis import RecommendedAction, RootCauseAnalysis
from app.schemas.events import Severity
from app.schemas.incidents import Incident, IncidentStatus
from app.schemas.response import ActionAuditRecord

router = APIRouter(
    prefix="/api/v1",
    tags=["incidents"],
    dependencies=[Depends(require_api_key)],
)


@router.post("/events", response_model=list[Incident])
async def ingest_events(batch: EventBatch, services: ApiServicesDependency) -> list[Incident]:
    """Run already-normalized events through the deterministic incident pipeline.

    Correlation runs over every retained event (services.events.get_all()), not just this
    request's batch. Real collectors post events incrementally as they occur, often on
    separate requests spread across the correlation window — running the pipeline against
    only the current batch would mean a rule spanning multiple source systems could never
    fire outside of a single bulk-loaded request. Incident IDs are deterministic (see
    CorrelationEngine), so re-evaluating retained history on every call is idempotent.
    """
    services.events.add_all(batch.events)
    incidents = run_pipeline(services.events.get_all())
    for incident in incidents:
        created = services.incidents.upsert(incident)
        await services.connections.broadcast(
            RealtimeMessage[Incident](
                type=(
                    RealtimeEventType.INCIDENT_CREATED
                    if created
                    else RealtimeEventType.INCIDENT_UPDATED
                ),
                payload=incident,
            )
        )
    return incidents


@router.get("/incidents", response_model=list[Incident])
async def list_incidents(
    services: ApiServicesDependency,
    severity: Severity | None = None,
    incident_status: Annotated[IncidentStatus | None, Query(alias="status")] = None,
    sort_by: IncidentSortField = IncidentSortField.CREATED_AT,
    order: SortOrder = SortOrder.DESC,
) -> list[Incident]:
    """List retained incidents using explicit filters and one supported sort key."""
    incidents = services.incidents.list_all()
    if severity is not None:
        incidents = [incident for incident in incidents if incident.severity is severity]
    if incident_status is not None:
        incidents = [incident for incident in incidents if incident.status is incident_status]
    reverse = order is SortOrder.DESC
    if sort_by is IncidentSortField.CREATED_AT:
        incidents.sort(key=lambda incident: incident.created_at, reverse=reverse)
    else:
        incidents.sort(key=lambda incident: incident.risk_score, reverse=reverse)
    return incidents


@router.get(
    "/incidents/{incident_id}",
    response_model=IncidentDetail,
    responses={status.HTTP_404_NOT_FOUND: {"model": ApiError}},
)
async def get_incident(
    incident_id: UUID, services: ApiServicesDependency
) -> IncidentDetail | JSONResponse:
    """Return an incident with retained normalized evidence and optional analysis."""
    incident = services.incidents.get(incident_id)
    if incident is None:
        return _error(status.HTTP_404_NOT_FOUND, "incident_not_found", "Incident was not found")
    return IncidentDetail(
        incident=incident,
        evidence=services.events.get_many(incident.event_ids),
        analysis=services.incidents.get_analysis(incident.id),
    )


@router.post(
    "/incidents/{incident_id}/analyze",
    response_model=RootCauseAnalysis,
    responses={
        status.HTTP_404_NOT_FOUND: {"model": ApiError},
        status.HTTP_422_UNPROCESSABLE_CONTENT: {"model": ApiError},
        status.HTTP_502_BAD_GATEWAY: {"model": ApiError},
        status.HTTP_503_SERVICE_UNAVAILABLE: {"model": ApiError},
    },
)
async def analyze_incident(
    incident_id: UUID, services: ApiServicesDependency
) -> RootCauseAnalysis | JSONResponse:
    """Generate and retain one explicit on-demand structured analysis."""
    incident = services.incidents.get(incident_id)
    if incident is None:
        return _error(status.HTTP_404_NOT_FOUND, "incident_not_found", "Incident was not found")
    evidence = services.events.get_many(incident.event_ids)
    try:
        analysis_engine = services.analysis_engine_factory()
        analysis = await analysis_engine.analyze(incident, evidence)
    except AnalysisConfigurationError as exc:
        return _error(status.HTTP_503_SERVICE_UNAVAILABLE, "analysis_not_configured", str(exc))
    except AnalysisInputError as exc:
        return _error(status.HTTP_422_UNPROCESSABLE_CONTENT, "analysis_input_error", str(exc))
    except AnalysisGenerationError as exc:
        return _error(status.HTTP_502_BAD_GATEWAY, "analysis_generation_failed", str(exc))
    services.incidents.save_analysis(incident.id, analysis)
    await services.connections.broadcast(
        RealtimeMessage[Incident](
            type=RealtimeEventType.INCIDENT_UPDATED,
            payload=incident,
        )
    )
    return analysis


@router.post(
    "/incidents/{incident_id}/actions",
    response_model=ActionAuditRecord,
    responses={status.HTTP_404_NOT_FOUND: {"model": ApiError}},
)
async def request_action(
    incident_id: UUID,
    action: RecommendedAction,
    services: ApiServicesDependency,
) -> ActionAuditRecord | JSONResponse:
    """Submit a typed recommendation to the existing simulated response engine."""
    incident = services.incidents.get(incident_id)
    if incident is None:
        return _error(status.HTTP_404_NOT_FOUND, "incident_not_found", "Incident was not found")
    evidence = services.events.get_many(incident.event_ids)
    record = services.response_engine.request_action(
        action,
        incident_id=incident.id,
        context=action_context_from_incident(incident, evidence),
    )
    await _broadcast_action(services, record)
    return record


@router.post(
    "/actions/{record_id}/approve",
    response_model=ActionAuditRecord,
    responses={
        status.HTTP_404_NOT_FOUND: {"model": ApiError},
        status.HTTP_409_CONFLICT: {"model": ApiError},
    },
)
async def approve_action(
    record_id: UUID,
    decision: ApprovalDecision,
    services: ApiServicesDependency,
) -> ActionAuditRecord | JSONResponse:
    """Approve a pending response record and simulate its registered handler."""
    try:
        record = services.response_engine.approve(record_id, decision.decided_by)
    except ActionRecordNotFoundError as exc:
        return _error(status.HTTP_404_NOT_FOUND, "action_not_found", str(exc))
    except InvalidActionTransitionError as exc:
        return _error(status.HTTP_409_CONFLICT, "invalid_action_transition", str(exc))
    await _broadcast_action(services, record)
    return record


@router.post(
    "/actions/{record_id}/reject",
    response_model=ActionAuditRecord,
    responses={
        status.HTTP_404_NOT_FOUND: {"model": ApiError},
        status.HTTP_409_CONFLICT: {"model": ApiError},
    },
)
async def reject_action(
    record_id: UUID,
    decision: RejectionDecision,
    services: ApiServicesDependency,
) -> ActionAuditRecord | JSONResponse:
    """Reject a pending response record without invoking its handler."""
    try:
        record = services.response_engine.reject(
            record_id,
            decision.decided_by,
            decision.reason,
        )
    except ActionRecordNotFoundError as exc:
        return _error(status.HTTP_404_NOT_FOUND, "action_not_found", str(exc))
    except InvalidActionTransitionError as exc:
        return _error(status.HTTP_409_CONFLICT, "invalid_action_transition", str(exc))
    await _broadcast_action(services, record)
    return record


async def _broadcast_action(
    services: ApiServicesDependency, record: ActionAuditRecord
) -> None:
    await services.connections.broadcast(
        RealtimeMessage[ActionAuditRecord](
            type=RealtimeEventType.ACTION_UPDATED,
            payload=record,
        )
    )


def _error(status_code: int, code: str, message: str) -> JSONResponse:
    payload = ApiError(code=code, message=message)
    return JSONResponse(status_code=status_code, content=payload.model_dump())
