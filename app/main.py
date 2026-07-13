"""WardHound ASGI application."""

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from app.api.health import router as health_router
from app.api.incidents import router as incident_router
from app.api.realtime import IncidentConnectionManager
from app.api.services import ApiServices
from app.api.websocket import router as websocket_router
from app.engines.analysis import create_analysis_engine_from_env
from app.engines.response import InMemoryApprovalStore, ResponseEngine
from app.stores.incidents import InMemoryEventStore, InMemoryIncidentStore


@dataclass(frozen=True, slots=True)
class Services:
    """Long-lived external service clients."""

    database: AsyncEngine
    redis: Redis


def _cors_origins() -> list[str]:
    configured = os.getenv("CORS_ORIGINS", "http://localhost:3000")
    return [origin.strip() for origin in configured.split(",") if origin.strip()]


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Initialize and release external service clients."""
    database = create_async_engine(
        os.getenv(
            "DATABASE_URL",
            "postgresql+asyncpg://wardhound:wardhound@localhost:5432/wardhound",
        )
    )
    redis: Redis = Redis.from_url(
        os.getenv("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True
    )
    app.state.services = Services(database=database, redis=redis)
    approval_store = InMemoryApprovalStore()
    app.state.api_services = ApiServices(
        incidents=InMemoryIncidentStore(),
        events=InMemoryEventStore(),
        response_engine=ResponseEngine(approval_store),
        analysis_engine_factory=create_analysis_engine_from_env,
        connections=IncidentConnectionManager(),
    )
    yield
    await redis.aclose()
    await database.dispose()


def create_app() -> FastAPI:
    """Create and configure the WardHound API."""
    application = FastAPI(title="WardHound API", docs_url="/docs", lifespan=lifespan)
    application.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins(),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    application.include_router(health_router)
    application.include_router(incident_router)
    application.include_router(websocket_router)
    return application


app = create_app()
