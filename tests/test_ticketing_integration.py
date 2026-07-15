from __future__ import annotations

import json
from uuid import UUID

import httpx
import pytest

from app.integrations.ticketing import TicketingClient, TicketingError

TICKETING_URL = "https://tickets.example.com/hooks/synthetic-secret-token"
INCIDENT_ID = UUID("00000000-0000-4000-8000-000000000017")


async def test_ticketing_webhook_returns_confirmed_ticket_id() -> None:
    captured_payload: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured_payload.update(json.loads(request.content))
        return httpx.Response(201, json={"ticket_id": "TKT-SYNTHETIC-0017"})

    async with TicketingClient(
        TICKETING_URL, transport=httpx.MockTransport(handler)
    ) as client:
        result = await client.create_ticket(
            "WardHound incident 17",
            "Open a cross-team tracking record.",
            INCIDENT_ID,
            "high",
        )

    assert captured_payload == {
        "title": "WardHound incident 17",
        "description": "Open a cross-team tracking record.",
        "incident_id": str(INCIDENT_ID),
        "severity": "high",
    }
    assert result.ticket_id == "TKT-SYNTHETIC-0017"
    assert result.status_code == 201
    assert "synthetic-secret-token" not in json.dumps(captured_payload)


async def test_ticketing_webhook_timeout_is_clean_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("synthetic timeout", request=request)

    async with TicketingClient(
        TICKETING_URL, transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(TicketingError, match="timed out") as error:
            await client.create_ticket("Title", "Description", INCIDENT_ID, "medium")

    assert error.value.status_code is None
    assert "synthetic-secret-token" not in str(error.value)


async def test_ticketing_webhook_non_success_is_clean_error() -> None:
    async with TicketingClient(
        TICKETING_URL,
        transport=httpx.MockTransport(lambda request: httpx.Response(503)),
    ) as client:
        with pytest.raises(TicketingError, match="HTTP 503") as error:
            await client.create_ticket("Title", "Description", INCIDENT_ID, "medium")

    assert error.value.status_code == 503
    assert "synthetic-secret-token" not in str(error.value)


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, json={}),
        httpx.Response(200, json={"ticket_id": "  "}),
        httpx.Response(200, json={"ticket_id": None}),
        httpx.Response(200, text="not-json"),
    ],
)
async def test_ticketing_webhook_requires_usable_ticket_id(
    response: httpx.Response,
) -> None:
    async with TicketingClient(
        TICKETING_URL,
        transport=httpx.MockTransport(lambda request: response),
    ) as client:
        with pytest.raises(TicketingError, match="did not return a ticket identifier") as error:
            await client.create_ticket("Title", "Description", INCIDENT_ID, "medium")

    assert error.value.status_code == 200
