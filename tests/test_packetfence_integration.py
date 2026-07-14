from __future__ import annotations

import httpx
import pytest

from app.integrations.packetfence import PacketFenceClient, PacketFenceError


async def test_isolate_node_uses_documented_security_event_contract() -> None:
    async def respond(request: httpx.Request) -> httpx.Response:
        assert request.method == "PUT"
        assert request.url.path == "/api/v1/node/AA:BB:CC:DD:EE:FF/apply_security_event"
        assert request.headers["Authorization"] == "synthetic-api-token"
        assert request.content == b'{"security_event_id":"synthetic-isolation-event"}'
        return httpx.Response(200, json={"id": 42})

    async with PacketFenceClient(
        "https://10.20.30.40:9999",
        "synthetic-api-token",
        transport=httpx.MockTransport(respond),
    ) as client:
        result = await client.isolate_node(
            "AA:BB:CC:DD:EE:FF", "synthetic-isolation-event"
        )

    assert result.status_code == 200
    assert result.security_event_record_id == 42


async def test_isolate_node_translates_timeout() -> None:
    async def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("synthetic timeout", request=request)

    async with PacketFenceClient(
        "https://10.20.30.40:9999",
        "synthetic-api-token",
        transport=httpx.MockTransport(timeout),
    ) as client:
        with pytest.raises(PacketFenceError, match="timed out"):
            await client.isolate_node("AA:BB:CC:DD:EE:FF", "synthetic-isolation-event")


async def test_isolate_node_translates_connection_error() -> None:
    async def disconnect(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("synthetic connection failure", request=request)

    async with PacketFenceClient(
        "https://10.20.30.40:9999",
        "synthetic-api-token",
        transport=httpx.MockTransport(disconnect),
    ) as client:
        with pytest.raises(PacketFenceError, match="could not connect"):
            await client.isolate_node("AA:BB:CC:DD:EE:FF", "synthetic-isolation-event")


async def test_isolate_node_translates_error_response_without_body() -> None:
    async def reject(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"message": "synthetic upstream detail"})

    async with PacketFenceClient(
        "https://10.20.30.40:9999",
        "synthetic-api-token",
        transport=httpx.MockTransport(reject),
    ) as client:
        with pytest.raises(PacketFenceError, match="HTTP 503") as caught:
            await client.isolate_node("AA:BB:CC:DD:EE:FF", "synthetic-isolation-event")

    assert caught.value.status_code == 503
    assert "upstream detail" not in str(caught.value)


async def test_isolate_node_rejects_success_without_security_event_id() -> None:
    async def incomplete(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": "success"})

    async with PacketFenceClient(
        "https://10.20.30.40:9999",
        "synthetic-api-token",
        transport=httpx.MockTransport(incomplete),
    ) as client:
        with pytest.raises(PacketFenceError, match="did not return a security event id"):
            await client.isolate_node("AA:BB:CC:DD:EE:FF", "synthetic-isolation-event")
