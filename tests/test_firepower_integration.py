from __future__ import annotations

import json

import httpx
import pytest

from app.integrations.firepower import FirepowerClient, FirepowerError

BASE_URL = "https://fmc.corp.example.com"
GROUP_ID = "group-synthetic-0042"
DOMAIN_UUID = "domain-synthetic-0042"
TARGET_IP = "10.20.30.40"
GROUP_PATH = f"/api/fmc_config/v1/domain/{DOMAIN_UUID}/object/networkgroups/{GROUP_ID}"


def network_group(*, blocked: bool = False) -> dict[str, object]:
    literals: list[dict[str, str]] = [{"type": "Network", "value": "10.30.0.0/16"}]
    if blocked:
        literals.append({"type": "Host", "value": TARGET_IP})
    return {
        "id": GROUP_ID,
        "name": "WardHound Dynamic Blocklist",
        "type": "NetworkGroup",
        "description": "Synthetic deny-rule source group.",
        "objects": [{"id": "network-object-synthetic-0042", "type": "Network"}],
        "literals": literals,
        "metadata": {"readOnly": {"state": False}},
    }


def token_response() -> httpx.Response:
    return httpx.Response(
        204,
        headers={"X-auth-access-token": "synthetic-access-token", "DOMAIN_UUID": DOMAIN_UUID},
    )


async def test_add_blocklist_member_authenticates_updates_and_confirms() -> None:
    requests: list[httpx.Request] = []

    async def respond(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/api/fmc_platform/v1/auth/generatetoken":
            assert request.method == "POST"
            assert request.headers["Authorization"].startswith("Basic ")
            assert request.content == b""
            return token_response()
        assert request.headers["X-auth-access-token"] == "synthetic-access-token"
        assert "Authorization" not in request.headers
        assert request.url.path == GROUP_PATH
        if request.method == "GET" and len(requests) == 2:
            return httpx.Response(200, json=network_group())
        if request.method == "PUT":
            payload = json.loads(request.content)
            assert payload["literals"][-1] == {"type": "Host", "value": TARGET_IP}
            assert "metadata" not in payload
            return httpx.Response(200, json=payload)
        return httpx.Response(200, json=network_group(blocked=True))

    async with FirepowerClient(
        BASE_URL,
        "synthetic-api-user",
        "synthetic-api-password",
        transport=httpx.MockTransport(respond),
    ) as client:
        result = await client.add_blocklist_member(GROUP_ID, TARGET_IP)

    assert result.already_blocked is False
    assert result.enforcement_pending_deploy is True
    assert [request.method for request in requests] == ["POST", "GET", "PUT", "GET"]
    assert all("deployment" not in request.url.path for request in requests)


async def test_add_blocklist_member_is_idempotent_when_literal_exists() -> None:
    requests: list[httpx.Request] = []

    async def respond(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "POST":
            return token_response()
        return httpx.Response(200, json=network_group(blocked=True))

    async with FirepowerClient(
        BASE_URL,
        "synthetic-api-user",
        "synthetic-api-password",
        transport=httpx.MockTransport(respond),
    ) as client:
        result = await client.add_blocklist_member(GROUP_ID, TARGET_IP)

    assert result.already_blocked is True
    assert [request.method for request in requests] == ["POST", "GET"]


async def test_add_blocklist_member_reports_token_failure() -> None:
    async def reject_token(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401)

    async with FirepowerClient(
        BASE_URL,
        "synthetic-api-user",
        "synthetic-api-password",
        transport=httpx.MockTransport(reject_token),
    ) as client:
        with pytest.raises(FirepowerError, match="token generation returned HTTP 401"):
            await client.add_blocklist_member(GROUP_ID, TARGET_IP)


async def test_add_blocklist_member_reports_timeout_without_credentials() -> None:
    async def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("synthetic timeout", request=request)

    async with FirepowerClient(
        BASE_URL,
        "synthetic-api-user",
        "synthetic-api-password",
        transport=httpx.MockTransport(timeout),
    ) as client:
        with pytest.raises(FirepowerError, match="request timed out") as caught:
            await client.add_blocklist_member(GROUP_ID, TARGET_IP)

    assert "synthetic-api-password" not in str(caught.value)


async def test_add_blocklist_member_reports_object_not_found() -> None:
    async def respond(request: httpx.Request) -> httpx.Response:
        return token_response() if request.method == "POST" else httpx.Response(404)

    async with FirepowerClient(
        BASE_URL,
        "synthetic-api-user",
        "synthetic-api-password",
        transport=httpx.MockTransport(respond),
    ) as client:
        with pytest.raises(FirepowerError, match="Network Group was not found"):
            await client.add_blocklist_member(GROUP_ID, TARGET_IP)


async def test_add_blocklist_member_reports_put_failure() -> None:
    async def respond(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return token_response()
        if request.method == "GET":
            return httpx.Response(200, json=network_group())
        return httpx.Response(422)

    async with FirepowerClient(
        BASE_URL,
        "synthetic-api-user",
        "synthetic-api-password",
        transport=httpx.MockTransport(respond),
    ) as client:
        with pytest.raises(FirepowerError, match="update returned HTTP 422"):
            await client.add_blocklist_member(GROUP_ID, TARGET_IP)


async def test_add_blocklist_member_rejects_unconfirmed_put() -> None:
    get_count = 0

    async def respond(request: httpx.Request) -> httpx.Response:
        nonlocal get_count
        if request.method == "POST":
            return token_response()
        if request.method == "GET":
            get_count += 1
            return httpx.Response(200, json=network_group())
        return httpx.Response(200, json=network_group(blocked=True))

    async with FirepowerClient(
        BASE_URL,
        "synthetic-api-user",
        "synthetic-api-password",
        transport=httpx.MockTransport(respond),
    ) as client:
        with pytest.raises(FirepowerError, match="confirmation read did not show"):
            await client.add_blocklist_member(GROUP_ID, TARGET_IP)

    assert get_count == 2


def test_client_rejects_non_https_base_url() -> None:
    with pytest.raises(ValueError, match="must use https"):
        FirepowerClient(
            "http://fmc.corp.example.com",
            "synthetic-api-user",
            "synthetic-api-password",
        )
