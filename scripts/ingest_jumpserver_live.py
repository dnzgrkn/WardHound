"""Run one operator-selected JumpServer lookback through production adaptations."""

from __future__ import annotations

import argparse
import asyncio
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
from dotenv import load_dotenv

from app.collectors.jumpserver_live import JumpServerAccessKeyAuth, LiveJumpServerCollector

load_dotenv(Path(__file__).resolve().parent.parent / ".env")


def _require_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise SystemExit(f"Missing required environment variable: {name}")
    return value


async def main(since_hours: float) -> None:
    collector = LiveJumpServerCollector()
    async with httpx.AsyncClient(
        base_url=_require_env("JUMPSERVER_BASE_URL"),
        headers={"Accept": "application/json"},
        auth=JumpServerAccessKeyAuth(
            _require_env("JUMPSERVER_ACCESS_KEY_ID"),
            _require_env("JUMPSERVER_ACCESS_KEY_SECRET"),
        ),
        timeout=30.0,
    ) as jumpserver_client:
        events = await collector.poll(
            jumpserver_client, datetime.now(UTC) - timedelta(hours=since_hours)
        )
    if not events:
        print("No new JumpServer activity found. Nothing to ingest.")
        return
    async with httpx.AsyncClient(
        base_url=os.getenv("WARDHOUND_API_URL", "http://localhost:8000"),
        headers={"X-API-Key": _require_env("WARDHOUND_API_KEY")},
        timeout=30.0,
    ) as wardhound_client:
        response = await wardhound_client.post(
            "/api/v1/events",
            json={"events": [event.model_dump(mode="json") for event in events]},
        )
        response.raise_for_status()
    print(f"Ingested {len(events)} normalized JumpServer event(s).")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--since-hours", type=float, default=24.0)
    args = parser.parse_args()
    asyncio.run(main(args.since_hours))
