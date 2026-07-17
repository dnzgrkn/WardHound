from __future__ import annotations

import json

import httpx
import pytest

from app.tasks.packetfence import PollSettings, poll_packetfence, run_poll_cycle

HEADER = "mac|computername|pid|category|status"
TASK_ID = "11111111-2222-3333-4444-555555555555"


class MemoryState:
    def __init__(self, values: set[str] | None = None) -> None:
        self.values = values or set()
        self.replacements: list[set[str]] = []

    async def get(self) -> set[str]:
        return set(self.values)

    async def replace(self, macs: set[str]) -> None:
        self.values = set(macs)
        self.replacements.append(set(macs))


def settings() -> PollSettings:
    return PollSettings(
        jumpserver_base_url="https://jumpserver.example.com",
        access_key_id="key-id",
        access_key_secret="key-secret",
        asset_name="pf-managed-asset",
        runas="ops-account",
        wardhound_api_url="http://api:8000",
        wardhound_api_key="api-key",
    )


@pytest.mark.parametrize(
    "missing",
    [
        "JUMPSERVER_BASE_URL",
        "JUMPSERVER_ACCESS_KEY_ID",
        "JUMPSERVER_ACCESS_KEY_SECRET",
        "PACKETFENCE_JUMPSERVER_ASSET_NAME",
        "PACKETFENCE_JUMPSERVER_RUNAS",
    ],
)
def test_five_signal_gate_makes_no_network_calls(
    monkeypatch: pytest.MonkeyPatch, missing: str
) -> None:
    for name in (
        "JUMPSERVER_BASE_URL",
        "JUMPSERVER_ACCESS_KEY_ID",
        "JUMPSERVER_ACCESS_KEY_SECRET",
        "PACKETFENCE_JUMPSERVER_ASSET_NAME",
        "PACKETFENCE_JUMPSERVER_RUNAS",
    ):
        monkeypatch.setenv(name, "configured")
    monkeypatch.delenv(missing)

    async def unexpected_run(_settings: PollSettings) -> int:
        raise AssertionError("unconfigured polling must not construct network clients")

    monkeypatch.setattr("app.tasks.packetfence._run_from_env", unexpected_run)
    assert poll_packetfence() == 0


def jumpserver_transport(outputs: list[str]) -> httpx.MockTransport:
    cycle = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal cycle
        path = request.url.path
        if path == "/api/v1/assets/assets/":
            return httpx.Response(200, json=[{"id": "asset-id", "name": "pf-managed-asset"}])
        if path == "/api/v1/ops/jobs/":
            return httpx.Response(201, json={"task_id": TASK_ID})
        if "/task-detail/" in path:
            return httpx.Response(200, json={"is_finished": True, "status": {"value": "success"}})
        if path.endswith("/log/"):
            output = outputs[cycle]
            cycle += 1
            return httpx.Response(200, json={"data": f"host | CHANGED | rc=0 >>\n{output}\n"})
        raise AssertionError(request.url)

    return httpx.MockTransport(handler)


def table(*rows: str) -> str:
    return "0" if not rows else f"{len(rows)}\n{HEADER}\n" + "\n".join(rows)


@pytest.mark.asyncio
async def test_consecutive_snapshot_ingests_mac_only_once() -> None:
    row = "00:11:22:33:44:55||someuser|Quarantine|unreg"
    state = MemoryState()
    ingests: list[httpx.Request] = []

    def ingest(request: httpx.Request) -> httpx.Response:
        ingests.append(request)
        return httpx.Response(200, json=[])

    async with (
        httpx.AsyncClient(
            base_url=settings().jumpserver_base_url,
            transport=jumpserver_transport([table(row), table(row)]),
        ) as jumpserver,
        httpx.AsyncClient(
            base_url=settings().wardhound_api_url, transport=httpx.MockTransport(ingest)
        ) as wardhound,
    ):
        assert await run_poll_cycle(settings(), state, jumpserver, wardhound) == 1
        assert await run_poll_cycle(settings(), state, jumpserver, wardhound) == 0

    assert len(ingests) == 1
    body = json.loads(ingests[0].content)
    assert body["events"][0]["related_entities"][0]["username"] == "someuser"


@pytest.mark.asyncio
async def test_failed_ingestion_does_not_advance_quarantine_snapshot() -> None:
    row = "00:11:22:33:44:55||someuser|Quarantine|unreg"
    state = MemoryState()
    calls = 0

    def ingest(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503 if calls == 1 else 200, json={})

    async with (
        httpx.AsyncClient(
            base_url=settings().jumpserver_base_url,
            transport=jumpserver_transport([table(row), table(row)]),
        ) as jumpserver,
        httpx.AsyncClient(
            base_url=settings().wardhound_api_url, transport=httpx.MockTransport(ingest)
        ) as wardhound,
    ):
        with pytest.raises(httpx.HTTPStatusError):
            await run_poll_cycle(settings(), state, jumpserver, wardhound)
        assert state.values == set()
        assert await run_poll_cycle(settings(), state, jumpserver, wardhound) == 1

    assert calls == 2


@pytest.mark.asyncio
async def test_departed_mac_realerts_when_it_reenters_quarantine() -> None:
    row = "00:11:22:33:44:55||someuser|Quarantine|unreg"
    state = MemoryState()
    ingests: list[httpx.Request] = []

    def ingest(request: httpx.Request) -> httpx.Response:
        ingests.append(request)
        return httpx.Response(200, json=[])

    async with (
        httpx.AsyncClient(
            base_url=settings().jumpserver_base_url,
            transport=jumpserver_transport([table(row), table(), table(row)]),
        ) as jumpserver,
        httpx.AsyncClient(
            base_url=settings().wardhound_api_url, transport=httpx.MockTransport(ingest)
        ) as wardhound,
    ):
        assert await run_poll_cycle(settings(), state, jumpserver, wardhound) == 1
        assert await run_poll_cycle(settings(), state, jumpserver, wardhound) == 0
        assert state.values == set()
        assert await run_poll_cycle(settings(), state, jumpserver, wardhound) == 1

    assert len(ingests) == 2
