"""Bounded scheduled Active Directory poll through JumpServer Ops."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol

import httpx
from celery import shared_task
from redis.asyncio import Redis

from app.collectors.active_directory import ActiveDirectoryCollector
from app.collectors.jumpserver_live import JumpServerAccessKeyAuth
from app.collectors.jumpserver_ops import JumpServerOpsClient

logger = logging.getLogger(__name__)
WATERMARK_KEY = "wardhound:collectors:ad:last_successful_poll"
_collector = ActiveDirectoryCollector()


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
            raise ValueError("Active Directory watermark must include a timezone")
        return parsed.astimezone(UTC)

    async def set(self, value: datetime) -> None:
        await self.redis.set(WATERMARK_KEY, value.astimezone(UTC).isoformat())


@dataclass(frozen=True, slots=True)
class PollSettings:
    jumpserver_base_url: str
    access_key_id: str
    access_key_secret: str
    asset_name: str
    runas: str
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
                "AD_JUMPSERVER_ASSET_NAME",
                "AD_JUMPSERVER_RUNAS",
            )
        }
        if not all(required.values()):
            return None
        return cls(
            jumpserver_base_url=required["JUMPSERVER_BASE_URL"],
            access_key_id=required["JUMPSERVER_ACCESS_KEY_ID"],
            access_key_secret=required["JUMPSERVER_ACCESS_KEY_SECRET"],
            asset_name=required["AD_JUMPSERVER_ASSET_NAME"],
            runas=required["AD_JUMPSERVER_RUNAS"],
            wardhound_api_url=os.getenv("WARDHOUND_API_URL", "http://api:8000").strip(),
            wardhound_api_key=os.environ["WARDHOUND_API_KEY"],
            initial_lookback_seconds=int(os.getenv("AD_INITIAL_LOOKBACK_SECONDS", "300")),
        )


def build_powershell_command(since: datetime) -> str:
    """Build the validated Event ID 4625 XML query for a single stdout result."""
    since_utc = since.astimezone(UTC).isoformat().replace("+00:00", "Z")
    query = (
        "$events = Get-WinEvent -FilterHashtable "
        "@{ LogName = 'Security'; Id = 4625; StartTime = $since } "
        "-ErrorAction SilentlyContinue"
    )
    return f"""$since = [datetime]::Parse('{since_utc}').ToUniversalTime()
{query}
$records = foreach ($event in $events) {{
    [xml]$xml = $event.ToXml()
    $data = @{{}}
    foreach ($d in $xml.Event.EventData.Data) {{
        if ($d.Name) {{ $data[$d.Name] = $d.'#text' }}
    }}
    $systemTime = [datetime]$xml.Event.System.TimeCreated.SystemTime
    [PSCustomObject]@{{
        EventID          = [int]$xml.Event.System.EventID
        Computer         = $xml.Event.System.Computer
        TargetUserName   = $data['TargetUserName']
        TargetDomainName = $data['TargetDomainName']
        TimeCreated      = $systemTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        IpAddress        = $data['IpAddress']
    }}
}}
ConvertTo-Json -InputObject @($records) -Depth 4 -Compress"""


async def run_poll_cycle(
    settings: PollSettings,
    watermark: WatermarkStore,
    jumpserver_client: httpx.AsyncClient,
    wardhound_client: httpx.AsyncClient,
    *,
    cutoff: datetime | None = None,
) -> int:
    """Poll one closed time window, ingest it, then commit its watermark."""
    cycle_cutoff = (cutoff or datetime.now(UTC)).astimezone(UTC)
    since = await watermark.get()
    if since is None:
        since = cycle_cutoff - timedelta(seconds=settings.initial_lookback_seconds)
    stdout = await JumpServerOpsClient(jumpserver_client).run(
        module="win_shell",
        args=build_powershell_command(since),
        runas=settings.runas,
        asset_name=settings.asset_name,
        name="WardHound Active Directory security event poll",
    )
    records = json.loads(stdout)
    if not isinstance(records, list):
        raise ValueError("Active Directory command output must be a JSON array")
    events = [_collector.process(record) for record in records]
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
            )
    finally:
        await redis.aclose()


@shared_task(name="app.tasks.active_directory.poll_active_directory")
def poll_active_directory() -> int:
    """Celery entry point; each invocation owns one bounded async event loop."""
    settings = PollSettings.from_env()
    if settings is None:
        logger.info("Active Directory polling skipped: JumpServer Ops collector is not configured")
        return 0
    count = asyncio.run(_run_from_env(settings))
    logger.info("Active Directory polling completed", extra={"event_count": count})
    return count
