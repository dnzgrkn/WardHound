from __future__ import annotations

import base64
import hashlib
import hmac
from urllib.parse import parse_qsl, quote, urlencode

import httpx
import pytest

from app.integrations.duo import DuoClient, DuoError

HOSTNAME = "api-synthetic.duosecurity.com"
INTEGRATION_KEY = "DIXXXXXXXXXXXXXXXXXX"
SECRET_KEY = "synthetic-secret-key"
FIXED_DATE = "Tue, 14 Jul 2026 12:00:00 GMT"
USER_ID = "DUXXXXXXXXXXXXXXXXXX"
PHONE_ID = "DPXXXXXXXXXXXXXXXXXX"
PUSH_ID = "push-synthetic-0042"


def _user() -> dict[str, object]:
    return {
        "user_id": USER_ID,
        "username": "jdoe",
        "status": "active",
        "is_enrolled": True,
        "phones": [
            {
                "phone_id": PHONE_ID,
                "activated": True,
                "capabilities": ["push", "mobile_otp"],
            }
        ],
    }


def _assert_duo_signature(request: httpx.Request) -> None:
    if request.method == "GET":
        parameters = urlencode(
            sorted(parse_qsl(request.url.query.decode("ascii"))),
            quote_via=quote,
            safe="~",
        )
    else:
        parameters = request.content.decode("ascii")
    canonical = "\n".join(
        (
            FIXED_DATE,
            request.method,
            HOSTNAME,
            request.url.path,
            parameters,
        )
    )
    signature = hmac.new(SECRET_KEY.encode(), canonical.encode("ascii"), hashlib.sha1).hexdigest()
    credentials = base64.b64encode(f"{INTEGRATION_KEY}:{signature}".encode("ascii")).decode("ascii")
    assert request.headers["Date"] == FIXED_DATE
    assert request.headers["Authorization"] == f"Basic {credentials}"


async def test_verification_push_is_signed_and_confirmed() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        _assert_duo_signature(request)
        if request.url.path == "/admin/v1/users":
            assert dict(request.url.params) == {"username": "jdoe"}
            return httpx.Response(200, json={"stat": "OK", "response": [_user()]})
        if request.url.path.endswith("/send_verification_push"):
            assert request.method == "POST"
            assert request.content == f"phone_id={PHONE_ID}".encode()
            return httpx.Response(
                200,
                json={
                    "stat": "OK",
                    "response": {"push_id": PUSH_ID, "confirmation_code": "004200"},
                },
            )
        if request.url.path.endswith("/verification_push_response"):
            assert dict(request.url.params) == {"push_id": PUSH_ID}
            return httpx.Response(
                200,
                json={
                    "stat": "OK",
                    "response": {"push_id": PUSH_ID, "result": "approve"},
                },
            )
        assert request.url.path == f"/admin/v1/users/{USER_ID}"
        return httpx.Response(200, json={"stat": "OK", "response": _user()})

    async with DuoClient(
        HOSTNAME,
        INTEGRATION_KEY,
        SECRET_KEY,
        transport=httpx.MockTransport(handler),
        date_factory=lambda: FIXED_DATE,
    ) as client:
        result = await client.require_verification("jdoe")

    assert result.verification_confirmed is True
    assert [request.method for request in requests] == ["GET", "POST", "GET", "GET"]


async def test_verification_push_rejects_unknown_user() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, json={"stat": "OK", "response": []})
    )
    async with DuoClient(HOSTNAME, INTEGRATION_KEY, SECRET_KEY, transport=transport) as client:
        with pytest.raises(DuoError, match="user was not found"):
            await client.require_verification("jdoe")


async def test_verification_push_rejects_confirmation_mismatch() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/admin/v1/users":
            return httpx.Response(200, json={"stat": "OK", "response": [_user()]})
        if request.url.path.endswith("/send_verification_push"):
            return httpx.Response(200, json={"stat": "OK", "response": {"push_id": PUSH_ID}})
        return httpx.Response(
            200,
            json={
                "stat": "OK",
                "response": {"push_id": PUSH_ID, "result": "deny"},
            },
        )

    async with DuoClient(
        HOSTNAME, INTEGRATION_KEY, SECRET_KEY, transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(DuoError, match="not approved.*deny"):
            await client.require_verification("jdoe")


async def test_verification_push_handles_rejected_signature() -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(401))
    async with DuoClient(HOSTNAME, INTEGRATION_KEY, SECRET_KEY, transport=transport) as client:
        with pytest.raises(DuoError, match="HTTP 401") as error:
            await client.require_verification("jdoe")

    assert error.value.status_code == 401


@pytest.mark.parametrize(
    ("exception", "message"),
    [
        (httpx.ReadTimeout("synthetic timeout"), "timed out"),
        (httpx.ConnectError("synthetic connection failure"), "could not connect"),
    ],
)
async def test_verification_push_handles_transport_failures(
    exception: httpx.RequestError, message: str
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise exception

    async with DuoClient(
        HOSTNAME,
        INTEGRATION_KEY,
        SECRET_KEY,
        transport=httpx.MockTransport(handler),
    ) as client:
        with pytest.raises(DuoError, match=message):
            await client.require_verification("jdoe")
