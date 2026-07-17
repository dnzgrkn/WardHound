"""Bounded scheduled JumpServer poll-and-ingest cycle."""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol

import httpx
from celery import shared_task
from redis.asyncio import Redis

from app.collectors.jumpserver_live import JumpServerAccessKeyAuth, LiveJumpServerCollector

logger = logging.getLogger(__name__)
WATERMARK_KEY = "wardhound:collectors:jumpserver:last_successful_poll"
_collector = LiveJumpServerCollector()


class WatermarkStore(Protocol):
    async def get(self) -> datetime | None: ...

    async def set(self, value: datetime) -> None: ...


class RedisWatermarkStore:
    def __init__(self, redis: Redis) -> None:
        self.redis = redis

    async def get(self) -> datetime | None:
        value = await self.redis.get(WATERMARK_KEY)
        if value is None:
            return None
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            raise ValueError("JumpServer watermark must include a timezone")
        return parsed.astimezone(UTC)

    async def set(self, value: datetime) -> None:
        await self.redis.set(WATERMARK_KEY, value.astimezone(UTC).isoformat())


@dataclass(frozen=True, slots=True)
class PollSettings:
    jumpserver_base_url: str
    access_key_id: str
    access_key_secret: str
    wardhound_api_url: str
    wardhound_api_key: str
    initial_lookback_seconds: int = 300

    @classmethod
    def from_env(cls) -> PollSettings | None:
        required = {
            name: os.getenv(name, "").strip()
            for name in (
                "JUMPSERVER_BASE_URL",
                "JUMPSERVER_ACCESS_KEY_ID",
                "JUMPSERVER_ACCESS_KEY_SECRET",
            )
        }
        if not all(required.values()):
            return None
        return cls(
            jumpserver_base_url=required["JUMPSERVER_BASE_URL"],
            access_key_id=required["JUMPSERVER_ACCESS_KEY_ID"],
            access_key_secret=required["JUMPSERVER_ACCESS_KEY_SECRET"],
            wardhound_api_url=os.getenv("WARDHOUND_API_URL", "http://api:8000").strip(),
            wardhound_api_key=os.environ["WARDHOUND_API_KEY"],
            initial_lookback_seconds=int(os.getenv("JUMPSERVER_INITIAL_LOOKBACK_SECONDS", "300")),
        )


async def run_poll_cycle(
    settings: PollSettings,
    watermark: WatermarkStore,
    jumpserver_client: httpx.AsyncClient,
    wardhound_client: httpx.AsyncClient,
    *,
    collector: LiveJumpServerCollector | None = None,
    cutoff: datetime | None = None,
) -> int:
    """Poll one closed time window, ingest it, then commit its watermark."""
    cycle_cutoff = (cutoff or datetime.now(UTC)).astimezone(UTC)
    since = await watermark.get()
    if since is None:
        since = cycle_cutoff - timedelta(seconds=settings.initial_lookback_seconds)
    events = await (collector or LiveJumpServerCollector()).poll(jumpserver_client, since)
    events = [event for event in events if since < event.occurred_at <= cycle_cutoff]
    if events:
        response = await wardhound_client.post(
            "/api/v1/events",
            json={"events": [event.model_dump(mode="json") for event in events]},
        )
        response.raise_for_status()
    await watermark.set(cycle_cutoff)
    return len(events)


async def _run_from_env(settings: PollSettings) -> int:
    redis: Redis = Redis.from_url(os.environ["REDIS_URL"], decode_responses=True)
    try:
        async with (
            httpx.AsyncClient(
                base_url=settings.jumpserver_base_url,
                headers={"Accept": "application/json"},
                auth=JumpServerAccessKeyAuth(settings.access_key_id, settings.access_key_secret),
                timeout=30.0,
            ) as jumpserver_client,
            httpx.AsyncClient(
                base_url=settings.wardhound_api_url,
                headers={"X-API-Key": settings.wardhound_api_key},
                timeout=30.0,
            ) as wardhound_client,
        ):
            return await run_poll_cycle(
                settings,
                RedisWatermarkStore(redis),
                jumpserver_client,
                wardhound_client,
                collector=_collector,
            )
    finally:
        await redis.aclose()


@shared_task(name="app.tasks.jumpserver.poll_jumpserver")
def poll_jumpserver() -> int:
    """Celery entry point; each invocation owns one bounded async event loop."""
    settings = PollSettings.from_env()
    if settings is None:
        logger.info("JumpServer polling skipped: AccessKey collector is not configured")
        return 0
    count = asyncio.run(_run_from_env(settings))
    logger.info("JumpServer polling completed", extra={"event_count": count})
    return count
