from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import cast

import httpx
import pytest

from app.tasks.active_directory import (
    PollSettings,
    build_powershell_command,
    poll_active_directory,
    run_poll_cycle,
)

TASK_ID = "11111111-2222-3333-4444-555555555555"


class MemoryWatermark:
    def __init__(self, value: datetime | None = None) -> None:
        self.value = value

    async def get(self) -> datetime | None:
        return self.value

    async def set(self, value: datetime) -> None:
        self.value = value


def settings() -> PollSettings:
    return PollSettings(
        jumpserver_base_url="https://jumpserver.example.com",
        access_key_id="key-id",
        access_key_secret="key-secret",
        asset_name="dc-managed-asset",
        runas="ops-account",
        wardhound_api_url="http://api:8000",
        wardhound_api_key="api-key",
        initial_lookback_seconds=300,
    )


@pytest.mark.parametrize(
    "missing",
    [
        "JUMPSERVER_BASE_URL",
        "JUMPSERVER_ACCESS_KEY_ID",
        "JUMPSERVER_ACCESS_KEY_SECRET",
        "AD_JUMPSERVER_ASSET_NAME",
        "AD_JUMPSERVER_RUNAS",
    ],
)
def test_five_signal_gate_makes_no_network_calls(
    monkeypatch: pytest.MonkeyPatch, missing: str
) -> None:
    names = (
        "JUMPSERVER_BASE_URL",
        "JUMPSERVER_ACCESS_KEY_ID",
        "JUMPSERVER_ACCESS_KEY_SECRET",
        "AD_JUMPSERVER_ASSET_NAME",
        "AD_JUMPSERVER_RUNAS",
    )
    for name in names:
        monkeypatch.setenv(name, "configured")
    monkeypatch.delenv(missing)

    async def unexpected_run(_settings: PollSettings) -> int:
        raise AssertionError("unconfigured polling must not construct network clients")

    monkeypatch.setattr("app.tasks.active_directory._run_from_env", unexpected_run)
    assert poll_active_directory() == 0


def event(at: str, username: str = "example-user") -> dict[str, object]:
    return {
        "EventID": 4625,
        "Computer": "dc.example.local",
        "TargetUserName": username,
        "TargetDomainName": "EXAMPLE",
        "TimeCreated": at,
        "IpAddress": "10.20.30.40",
    }


def jumpserver_transport(outputs: list[list[dict[str, object]]]) -> httpx.MockTransport:
    cycle = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal cycle
        path = request.url.path
        if path == "/api/v1/assets/assets/":
            return httpx.Response(200, json=[{"id": "asset-id", "name": "dc-managed-asset"}])
        if path == "/api/v1/ops/jobs/":
            return httpx.Response(201, json={"task_id": TASK_ID})
        if "/task-detail/" in path:
            return httpx.Response(200, json={"is_finished": True, "status": {"value": "success"}})
        if path.endswith("/log/"):
            output = json.dumps(outputs[cycle], separators=(",", ":"))
            cycle += 1
            return httpx.Response(
                200,
                json={"data": f"host | CHANGED | rc=0 >>\n{output}\n"},
            )
        raise AssertionError(request.url)

    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_watermark_narrows_second_poll_window() -> None:
    job_requests: list[httpx.Request] = []
    transport = jumpserver_transport([[], []])

    def recording_handler(request: httpx.Request) -> httpx.Response:
        job_requests.append(request)
        return cast(httpx.Response, transport.handler(request))

    watermark = MemoryWatermark()
    first_cutoff = datetime(2026, 7, 17, 10, 0, tzinfo=UTC)
    second_cutoff = datetime(2026, 7, 17, 10, 5, tzinfo=UTC)
    async with (
        httpx.AsyncClient(
            base_url=settings().jumpserver_base_url,
            transport=httpx.MockTransport(recording_handler),
        ) as jumpserver,
        httpx.AsyncClient(
            base_url=settings().wardhound_api_url,
            transport=httpx.MockTransport(lambda _request: httpx.Response(200, json=[])),
        ) as wardhound,
    ):
        await run_poll_cycle(settings(), watermark, jumpserver, wardhound, cutoff=first_cutoff)
        await run_poll_cycle(settings(), watermark, jumpserver, wardhound, cutoff=second_cutoff)

    jobs = [request for request in job_requests if request.url.path == "/api/v1/ops/jobs/"]
    assert "2026-07-17T09:55:00Z" in json.loads(jobs[0].content)["args"]
    assert "2026-07-17T10:00:00Z" in json.loads(jobs[1].content)["args"]
    assert watermark.value == second_cutoff


@pytest.mark.asyncio
async def test_failed_ingestion_does_not_advance_watermark() -> None:
    initial = datetime(2026, 7, 17, 10, 0, tzinfo=UTC)
    watermark = MemoryWatermark(initial)
    async with (
        httpx.AsyncClient(
            base_url=settings().jumpserver_base_url,
            transport=jumpserver_transport([[event("2026-07-17T10:01:00Z")]]),
        ) as jumpserver,
        httpx.AsyncClient(
            base_url=settings().wardhound_api_url,
            transport=httpx.MockTransport(
                lambda _request: httpx.Response(503, json={"detail": "unavailable"})
            ),
        ) as wardhound,
    ):
        with pytest.raises(httpx.HTTPStatusError):
            await run_poll_cycle(
                settings(),
                watermark,
                jumpserver,
                wardhound,
                cutoff=datetime(2026, 7, 17, 10, 5, tzinfo=UTC),
            )

    assert watermark.value == initial


@pytest.mark.asyncio
async def test_inclusive_watermark_boundary_event_is_not_reingested() -> None:
    initial = datetime(2026, 7, 17, 10, 0, tzinfo=UTC)
    watermark = MemoryWatermark(initial)
    ingests: list[httpx.Request] = []

    def ingest(request: httpx.Request) -> httpx.Response:
        ingests.append(request)
        return httpx.Response(200, json=[])

    async with (
        httpx.AsyncClient(
            base_url=settings().jumpserver_base_url,
            transport=jumpserver_transport([[event("2026-07-17T10:00:00Z")]]),
        ) as jumpserver,
        httpx.AsyncClient(
            base_url=settings().wardhound_api_url,
            transport=httpx.MockTransport(ingest),
        ) as wardhound,
    ):
        count = await run_poll_cycle(
            settings(),
            watermark,
            jumpserver,
            wardhound,
            cutoff=datetime(2026, 7, 17, 10, 5, tzinfo=UTC),
        )

    assert count == 0
    assert ingests == []


def test_powershell_command_uses_watermark_and_validated_field_list() -> None:
    command = build_powershell_command(datetime(2026, 7, 17, 9, 55, tzinfo=UTC))

    assert "$since = [datetime]::Parse('2026-07-17T09:55:00Z')" in command
    assert "Id = 4625; StartTime = $since" in command
    assert "powershell -Command" not in command
    assert "ConvertTo-Json -InputObject @($records) -Depth 4 -Compress" in command
    for field in (
        "EventID",
        "Computer",
        "TargetUserName",
        "TargetDomainName",
        "TimeCreated",
        "IpAddress",
    ):
        assert field in command
    assert "4740" not in command
    assert "4728" not in command
