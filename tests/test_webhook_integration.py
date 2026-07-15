from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import UUID

import httpx
import pytest

from app.integrations.webhook import WebhookClient, WebhookError

WEBHOOK_URL = "https://hooks.example.com/services/synthetic-bearer-token"
INCIDENT_ID = UUID("00000000-0000-4000-8000-000000000016")
TIMESTAMP = datetime(2026, 7, 15, 12, 30, tzinfo=UTC)


async def test_webhook_posts_slack_compatible_triage_payload() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["payload"] = json.loads(request.content)
        return httpx.Response(204)

    async with WebhookClient(
        WEBHOOK_URL, transport=httpx.MockTransport(handler)
    ) as client:
        status_code = await client.send_notification(
            INCIDENT_ID, "high", "Review repeated authentication failures.", TIMESTAMP
        )

    assert status_code == 204
    assert captured["payload"] == {
        "text": (
            "WardHound administrator notification\n"
            f"Incident: {INCIDENT_ID}\n"
            "Severity: high\n"
            "Summary: Review repeated authentication failures.\n"
            "Timestamp: 2026-07-15T12:30:00+00:00"
        )
    }


async def test_webhook_timeout_is_clean_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("synthetic timeout", request=request)

    async with WebhookClient(
        WEBHOOK_URL, transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(WebhookError, match="timed out") as error:
            await client.send_notification(INCIDENT_ID, "medium", "Review incident.", TIMESTAMP)

    assert error.value.status_code is None
    assert "synthetic-bearer-token" not in str(error.value)


async def test_webhook_non_success_is_clean_error() -> None:
    async with WebhookClient(
        WEBHOOK_URL,
        transport=httpx.MockTransport(lambda request: httpx.Response(503)),
    ) as client:
        with pytest.raises(WebhookError, match="HTTP 503") as error:
            await client.send_notification(INCIDENT_ID, "medium", "Review incident.", TIMESTAMP)

    assert error.value.status_code == 503
    assert "synthetic-bearer-token" not in str(error.value)


async def test_payload_excludes_webhook_credential_and_url() -> None:
    credential_marker = "synthetic-bearer-token"
    captured_body = b""

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal captured_body
        captured_body = request.content
        return httpx.Response(200)

    async with WebhookClient(
        WEBHOOK_URL, transport=httpx.MockTransport(handler)
    ) as client:
        await client.send_notification(
            INCIDENT_ID,
            "critical",
            "Review the correlated authentication incident.",
            TIMESTAMP,
        )

    outgoing_payload = captured_body.decode()
    assert credential_marker not in outgoing_payload
    assert WEBHOOK_URL not in outgoing_payload
    assert set(json.loads(outgoing_payload)) == {"text"}
