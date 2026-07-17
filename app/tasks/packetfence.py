"""Bounded scheduled PacketFence quarantine poll through JumpServer Ops."""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import Awaitable
from dataclasses import dataclass
from typing import Protocol, cast

import httpx
from celery import shared_task
from redis.asyncio import Redis

from app.collectors.jumpserver_live import JumpServerAccessKeyAuth
from app.collectors.jumpserver_ops import JumpServerOpsClient, parse_pipe_table
from app.collectors.packetfence import PacketFenceCollector
from app.schemas.events import EntityType, NormalizedEntity

logger = logging.getLogger(__name__)
KNOWN_QUARANTINE_KEY = "wardhound:collectors:packetfence:known_quarantine"
COMMAND = 'pfcmd node view category="Quarantine"'
_collector = PacketFenceCollector()


class QuarantineStateStore(Protocol):
    async def get(self) -> set[str]: ...

    async def replace(self, macs: set[str]) -> None: ...


class RedisQuarantineStateStore:
    def __init__(self, redis: Redis) -> None:
        self.redis = redis

    async def get(self) -> set[str]:
        values = await cast(Awaitable[set[str]], self.redis.smembers(KNOWN_QUARANTINE_KEY))
        return {value.lower() for value in values}

    async def replace(self, macs: set[str]) -> None:
        async with self.redis.pipeline(transaction=True) as pipeline:
            pipeline.delete(KNOWN_QUARANTINE_KEY)
            if macs:
                pipeline.sadd(KNOWN_QUARANTINE_KEY, *sorted(macs))
            await pipeline.execute()


@dataclass(frozen=True, slots=True)
class PollSettings:
    jumpserver_base_url: str
    access_key_id: str
    access_key_secret: str
    asset_name: str
    runas: str
    wardhound_api_url: str
    wardhound_api_key: str

    @classmethod
    def from_env(cls) -> PollSettings | None:
        required = {
            name: os.getenv(name, "").strip()
            for name in (
                "JUMPSERVER_BASE_URL",
                "JUMPSERVER_ACCESS_KEY_ID",
                "JUMPSERVER_ACCESS_KEY_SECRET",
                "PACKETFENCE_JUMPSERVER_ASSET_NAME",
                "PACKETFENCE_JUMPSERVER_RUNAS",
            )
        }
        if not all(required.values()):
            return None
        return cls(
            jumpserver_base_url=required["JUMPSERVER_BASE_URL"],
            access_key_id=required["JUMPSERVER_ACCESS_KEY_ID"],
            access_key_secret=required["JUMPSERVER_ACCESS_KEY_SECRET"],
            asset_name=required["PACKETFENCE_JUMPSERVER_ASSET_NAME"],
            runas=required["PACKETFENCE_JUMPSERVER_RUNAS"],
            wardhound_api_url=os.getenv("WARDHOUND_API_URL", "http://api:8000").strip(),
            wardhound_api_key=os.environ["WARDHOUND_API_KEY"],
        )


async def run_poll_cycle(
    settings: PollSettings,
    state: QuarantineStateStore,
    jumpserver_client: httpx.AsyncClient,
    wardhound_client: httpx.AsyncClient,
) -> int:
    stdout = await JumpServerOpsClient(jumpserver_client).run(
        module="shell",
        args=COMMAND,
        runas=settings.runas,
        asset_name=settings.asset_name,
        name="WardHound PacketFence quarantine poll",
    )
    records = parse_pipe_table(stdout)
    current = {record["mac"].lower() for record in records if record.get("mac")}
    new_macs = current - await state.get()
    events = []
    for record in records:
        mac = record.get("mac", "").lower()
        category = record.get("category", "")
        if mac not in new_macs or not PacketFenceCollector._is_isolation_role(category):
            continue
        event = _collector.process(
            {
                "kind": "node_state",
                "event_type": "device_quarantined",
                "mac": mac,
                "category": category,
                "status": record.get("status"),
                "source_host": "packetfence.local",
            }
        )
        pid = record.get("pid")
        if pid:
            event = event.model_copy(
                update={
                    "related_entities": [
                        *event.related_entities,
                        NormalizedEntity(entity_type=EntityType.USER, username=pid),
                    ]
                }
            )
        events.append(event)
    if events:
        response = await wardhound_client.post(
            "/api/v1/events",
            json={"events": [event.model_dump(mode="json") for event in events]},
        )
        response.raise_for_status()
    await state.replace(current)
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
                RedisQuarantineStateStore(redis),
                jumpserver_client,
                wardhound_client,
            )
    finally:
        await redis.aclose()


@shared_task(name="app.tasks.packetfence.poll_packetfence")
def poll_packetfence() -> int:
    settings = PollSettings.from_env()
    if settings is None:
        logger.info("PacketFence polling skipped: JumpServer Ops collector is not configured")
        return 0
    count = asyncio.run(_run_from_env(settings))
    logger.info("PacketFence polling completed", extra={"event_count": count})
    return count
