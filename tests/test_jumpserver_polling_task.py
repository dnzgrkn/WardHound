from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest

from app.tasks.jumpserver import PollSettings, poll_jumpserver, run_poll_cycle


class MemoryWatermark:
    def __init__(self) -> None:
        self.value: datetime | None = None

    async def get(self) -> datetime | None:
        return self.value

    async def set(self, value: datetime) -> None:
        self.value = value


def settings() -> PollSettings:
    return PollSettings(
        jumpserver_base_url="https://jumpserver.example.com",
        access_key_id="access-key-id",
        access_key_secret="access-key-secret",
        wardhound_api_url="http://api:8000",
        wardhound_api_key="api-key",
        initial_lookback_seconds=300,
    )


def test_unconfigured_task_makes_no_network_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "JUMPSERVER_BASE_URL",
        "JUMPSERVER_ACCESS_KEY_ID",
        "JUMPSERVER_ACCESS_KEY_SECRET",
    ):
        monkeypatch.delenv(name, raising=False)

    async def unexpected_run(_settings: PollSettings) -> int:
        raise AssertionError("unconfigured polling must not construct network clients")

    monkeypatch.setattr("app.tasks.jumpserver._run_from_env", unexpected_run)
    assert poll_jumpserver() == 0


@pytest.mark.asyncio
async def test_watermark_narrows_second_poll_window() -> None:
    jumpserver_requests: list[httpx.Request] = []

    def jumpserver_handler(request: httpx.Request) -> httpx.Response:
        jumpserver_requests.append(request)
        return httpx.Response(200, json=[])

    ingest_requests: list[httpx.Request] = []

    def ingest_handler(request: httpx.Request) -> httpx.Response:
        ingest_requests.append(request)
        return httpx.Response(200, json=[])

    watermark = MemoryWatermark()
    first_cutoff = datetime(2026, 7, 17, 10, 0, tzinfo=UTC)
    second_cutoff = datetime(2026, 7, 17, 10, 5, tzinfo=UTC)
    async with (
        httpx.AsyncClient(
            base_url=settings().jumpserver_base_url,
            transport=httpx.MockTransport(jumpserver_handler),
        ) as jumpserver_client,
        httpx.AsyncClient(
            base_url=settings().wardhound_api_url,
            transport=httpx.MockTransport(ingest_handler),
        ) as wardhound_client,
    ):
        await run_poll_cycle(
            settings(), watermark, jumpserver_client, wardhound_client, cutoff=first_cutoff
        )
        await run_poll_cycle(
            settings(), watermark, jumpserver_client, wardhound_client, cutoff=second_cutoff
        )

    assert jumpserver_requests[0].url.params["date_from"] == "2026/07/17 09:55:00 +0000"
    assert jumpserver_requests[3].url.params["date_from"] == "2026/07/17 10:00:00 +0000"
    assert watermark.value == second_cutoff
    assert ingest_requests == []


@pytest.mark.asyncio
async def test_failed_ingest_does_not_advance_watermark() -> None:
    login = {
        "id": "login-record-id",
        "username": "analyst",
        "status": {"value": True},
        "datetime": "2026/07/17 10:01:00 +0000",
        "type": {"value": "W"},
        "mfa": {"value": "0"},
    }

    def jumpserver_handler(request: httpx.Request) -> httpx.Response:
        body = [login] if "/audits/login-logs/" in request.url.path else []
        return httpx.Response(200, json=body)

    def failed_ingest(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"detail": "unavailable"})

    initial = datetime(2026, 7, 17, 10, 0, tzinfo=UTC)
    watermark = MemoryWatermark()
    watermark.value = initial
    async with (
        httpx.AsyncClient(
            base_url=settings().jumpserver_base_url,
            transport=httpx.MockTransport(jumpserver_handler),
        ) as jumpserver_client,
        httpx.AsyncClient(
            base_url=settings().wardhound_api_url,
            transport=httpx.MockTransport(failed_ingest),
        ) as wardhound_client,
    ):
        with pytest.raises(httpx.HTTPStatusError):
            await run_poll_cycle(
                settings(),
                watermark,
                jumpserver_client,
                wardhound_client,
                cutoff=datetime(2026, 7, 17, 10, 5, tzinfo=UTC),
            )

    assert watermark.value == initial


@pytest.mark.asyncio
async def test_inclusive_watermark_boundary_event_is_not_reingested() -> None:
    login = {
        "id": "boundary-login-record",
        "username": "analyst",
        "status": {"value": True},
        "datetime": "2026/07/17 10:00:00 +0000",
        "type": {"value": "W"},
        "mfa": {"value": "0"},
    }

    def jumpserver_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json=[login] if "/audits/login-logs/" in request.url.path else []
        )

    ingest_requests: list[httpx.Request] = []

    def ingest_handler(request: httpx.Request) -> httpx.Response:
        ingest_requests.append(request)
        return httpx.Response(200, json=[])

    watermark = MemoryWatermark()
    watermark.value = datetime(2026, 7, 17, 10, 0, tzinfo=UTC)
    async with (
        httpx.AsyncClient(
            base_url=settings().jumpserver_base_url,
            transport=httpx.MockTransport(jumpserver_handler),
        ) as jumpserver_client,
        httpx.AsyncClient(
            base_url=settings().wardhound_api_url,
            transport=httpx.MockTransport(ingest_handler),
        ) as wardhound_client,
    ):
        count = await run_poll_cycle(
            settings(),
            watermark,
            jumpserver_client,
            wardhound_client,
            cutoff=datetime(2026, 7, 17, 10, 5, tzinfo=UTC),
        )

    assert count == 0
    assert ingest_requests == []
