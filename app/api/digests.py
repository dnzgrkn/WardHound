"""Manual generation and history routes for daily security digests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from fastapi.responses import JSONResponse

from app.api.auth import require_api_key
from app.api.models import ApiError
from app.api.services import ApiServicesDependency
from app.engines.digest import DigestBuilder, DigestNarrativeGenerationError
from app.schemas.digest import DailyDigest

router = APIRouter(prefix="/api/v1/digests", tags=["digests"])


@router.post(
    "/generate",
    response_model=DailyDigest,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_api_key)],
    responses={status.HTTP_502_BAD_GATEWAY: {"model": ApiError}},
)
async def generate_digest(
    services: ApiServicesDependency,
) -> DailyDigest | JSONResponse:
    """Build and persist a digest for the immediately preceding 24 hours."""
    period_end = datetime.now(UTC)
    builder = DigestBuilder(
        services.events,
        services.incidents,
        services.response_engine.store,
        services.digest_narrative_engine_factory,
    )
    try:
        digest = await builder.build(period_end - timedelta(hours=24), period_end)
    except DigestNarrativeGenerationError as exc:
        return _error(
            status.HTTP_502_BAD_GATEWAY,
            "digest_narrative_generation_failed",
            str(exc),
        )
    await services.digests.append(digest)
    return digest


@router.get("", response_model=list[DailyDigest], dependencies=[Depends(require_api_key)])
async def list_digests(
    services: ApiServicesDependency,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> list[DailyDigest]:
    """Return generated digest history, most recent first."""
    return await services.digests.list_recent(limit)


@router.get(
    "/{digest_id}",
    response_model=DailyDigest,
    dependencies=[Depends(require_api_key)],
    responses={status.HTTP_404_NOT_FOUND: {"model": ApiError}},
)
async def get_digest(
    digest_id: UUID, services: ApiServicesDependency
) -> DailyDigest | JSONResponse:
    """Return one retained digest by UUID."""
    digest = await services.digests.get(digest_id)
    if digest is None:
        return _error(status.HTTP_404_NOT_FOUND, "digest_not_found", "Digest was not found")
    return digest


def _error(status_code: int, code: str, message: str) -> JSONResponse:
    payload = ApiError(code=code, message=message)
    return JSONResponse(status_code=status_code, content=payload.model_dump())
