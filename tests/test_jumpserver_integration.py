from __future__ import annotations

import httpx
import pytest

from app.integrations.jumpserver import JumpServerClient, JumpServerError

SESSION_ID = "session-synthetic-0042"


async def test_terminate_session_uses_verified_contract_and_confirms_finished() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert request.headers["Authorization"] == "Token synthetic-api-token"
        if request.method == "POST":
            assert request.url.path == "/api/v1/terminal/tasks/kill-session/"
            assert request.content == b'["session-synthetic-0042"]'
            return httpx.Response(200, json={"ok": [SESSION_ID]})
        assert request.url.path == f"/api/v1/terminal/sessions/{SESSION_ID}/"
        return httpx.Response(200, json={"id": SESSION_ID, "is_finished": True})

    async with JumpServerClient(
        "https://jumpserver.corp.example.com",
        "synthetic-api-token",
        transport=httpx.MockTransport(handler),
    ) as client:
        result = await client.terminate_session(SESSION_ID)

    assert result.termination_confirmed is True
    assert [request.method for request in requests] == ["POST", "GET"]


@pytest.mark.parametrize(
    ("exception", "message"),
    [
        (httpx.ReadTimeout("synthetic timeout"), "timed out"),
        (httpx.ConnectError("synthetic connection failure"), "could not connect"),
    ],
)
async def test_terminate_session_handles_transport_failures(
    exception: httpx.RequestError, message: str
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise exception

    async with JumpServerClient(
        "https://jumpserver.corp.example.com",
        "synthetic-api-token",
        transport=httpx.MockTransport(handler),
    ) as client:
        with pytest.raises(JumpServerError, match=message):
            await client.terminate_session(SESSION_ID)


async def test_terminate_session_rejects_non_success_response() -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(403))
    async with JumpServerClient(
        "https://jumpserver.corp.example.com",
        "synthetic-api-token",
        transport=transport,
    ) as client:
        with pytest.raises(JumpServerError, match="HTTP 403") as error:
            await client.terminate_session(SESSION_ID)

    assert error.value.status_code == 403


async def test_terminate_session_rejects_confirmation_mismatch() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(200, json={"ok": [SESSION_ID]})
        return httpx.Response(200, json={"id": SESSION_ID, "is_finished": False})

    async with JumpServerClient(
        "https://jumpserver.corp.example.com",
        "synthetic-api-token",
        transport=httpx.MockTransport(handler),
    ) as client:
        with pytest.raises(JumpServerError, match="did not show.*finished"):
            await client.terminate_session(SESSION_ID)
