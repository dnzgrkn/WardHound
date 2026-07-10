"""Service health endpoint."""

from typing import Annotated, Literal, Protocol

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from redis.asyncio import Redis
from redis.exceptions import RedisError
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine


class ServiceContainer(Protocol):
    """Resources required by health probes."""

    database: AsyncEngine
    redis: Redis[str]


class HealthResponse(BaseModel):
    """Connectivity status for WardHound and its dependencies."""

    status: Literal["healthy", "unhealthy"]
    database: Literal["connected", "disconnected"]
    redis: Literal["connected", "disconnected"]


router = APIRouter(tags=["health"])


def get_services(request: Request) -> ServiceContainer:
    """Return resources initialized during application lifespan."""
    services: ServiceContainer = request.app.state.services
    return services


async def check_database(
    services: Annotated[ServiceContainer, Depends(get_services)],
) -> bool:
    """Check that PostgreSQL accepts a trivial query."""
    try:
        async with services.database.connect() as connection:
            await connection.execute(text("SELECT 1"))
    except SQLAlchemyError:
        return False
    return True


async def check_redis(
    services: Annotated[ServiceContainer, Depends(get_services)],
) -> bool:
    """Check that Redis responds to PING."""
    try:
        return bool(await services.redis.ping())
    except RedisError:
        return False


@router.get(
    "/health",
    response_model=HealthResponse,
    responses={status.HTTP_503_SERVICE_UNAVAILABLE: {"model": HealthResponse}},
)
async def health(
    database_ok: Annotated[bool, Depends(check_database)],
    redis_ok: Annotated[bool, Depends(check_redis)],
) -> HealthResponse | JSONResponse:
    """Report application, PostgreSQL, and Redis readiness."""
    response = HealthResponse(
        status="healthy" if database_ok and redis_ok else "unhealthy",
        database="connected" if database_ok else "disconnected",
        redis="connected" if redis_ok else "disconnected",
    )
    if response.status == "unhealthy":
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content=response.model_dump(),
        )
    return response
