"""Scheduled daily digest generation, persistence, and optional delivery."""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import httpx
from celery import shared_task
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool

from app.digest_delivery import DigestDeliveryClient, DigestDeliverySettings
from app.engines.digest import (
    DigestBuilder,
    DigestNarrativeEngineFactory,
    DigestNarrativeGenerationError,
    create_digest_narrative_engine_from_env,
)
from app.engines.response import ApprovalStore
from app.schemas.digest import DailyDigest
from app.stores.digest import DigestStore
from app.stores.incidents import EventStore, IncidentStore
from app.stores.postgres import (
    PostgresApprovalStore,
    PostgresDigestStore,
    PostgresEventStore,
    PostgresIncidentStore,
)

logger = logging.getLogger(__name__)


async def generate_daily_digest(
    events: EventStore,
    incidents: IncidentStore,
    approvals: ApprovalStore,
    digests: DigestStore,
    narrative_engine_factory: DigestNarrativeEngineFactory | None,
    *,
    period_end: datetime | None = None,
    delivery_client_factory: Callable[[], DigestDeliveryClient | None] | None = None,
) -> DailyDigest:
    """Build and retain one trailing-day digest, degrading optional integrations."""
    end = (period_end or datetime.now(UTC)).astimezone(UTC)
    start = end - timedelta(hours=24)
    builder = DigestBuilder(events, incidents, approvals, narrative_engine_factory)
    try:
        digest = await builder.build(start, end)
    except DigestNarrativeGenerationError:
        logger.exception(
            "Daily digest narrative generation failed; persisting deterministic digest"
        )
        digest = await DigestBuilder(events, incidents, approvals).build(start, end)
    await digests.append(digest)

    factory = delivery_client_factory or _delivery_client_from_env
    delivery_client = factory()
    if delivery_client is None:
        logger.info(
            "Daily digest delivery skipped: webhook delivery is not configured",
            extra={"digest_id": str(digest.id)},
        )
    else:
        try:
            status_code = await delivery_client.deliver(digest)
            logger.info(
                "Daily digest delivered",
                extra={"digest_id": str(digest.id), "status_code": status_code},
            )
        except httpx.HTTPError:
            logger.exception(
                "Daily digest delivery failed after persistence",
                extra={"digest_id": str(digest.id)},
            )
    return digest


def _delivery_client_from_env() -> DigestDeliveryClient | None:
    settings = DigestDeliverySettings.from_env()
    return DigestDeliveryClient(settings) if settings is not None else None


async def _run_from_env() -> DailyDigest:
    database: AsyncEngine = create_async_engine(
        os.environ["DATABASE_URL"], poolclass=NullPool
    )
    try:
        approvals = PostgresApprovalStore(database)
        return await generate_daily_digest(
            PostgresEventStore(database),
            PostgresIncidentStore(database),
            approvals,
            PostgresDigestStore(database),
            create_digest_narrative_engine_from_env,
        )
    finally:
        await database.dispose()


@shared_task(name="app.tasks.digest.generate_daily_digest")
def scheduled_daily_digest() -> str:
    """Celery entry point owning one bounded async database and delivery cycle."""
    digest = asyncio.run(_run_from_env())
    logger.info("Daily digest generated and persisted", extra={"digest_id": str(digest.id)})
    return str(digest.id)
