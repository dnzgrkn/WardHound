from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest

from app.collectors.jumpserver import JumpServerCollector
from app.schemas.events import EntityType, NormalizedEventType


@pytest.mark.parametrize(
    ("source_type", "expected"),
    [
        ("session_started", NormalizedEventType.SESSION_STARTED),
        ("session_ended", NormalizedEventType.SESSION_ENDED),
        ("privileged_command_executed", NormalizedEventType.PRIVILEGED_COMMAND_EXECUTED),
        ("session_anomaly_detected", NormalizedEventType.SESSION_ANOMALY_DETECTED),
        ("auth_failed", NormalizedEventType.AUTH_FAILED),
    ],
)
def test_normalizes_supported_event_types(source_type: str, expected: NormalizedEventType) -> None:
    event = JumpServerCollector().process(
        {
            "event_type": source_type,
            "username": "svc-test",
            "timestamp": "2026-07-10T09:30:00Z",
            "source_host": "jump-01.example.test",
            "target_host": "SRV-TEST-0042",
            "session_id": "session-fake-42",
        }
    )

    assert event.event_type is expected
    assert event.primary_entity.entity_type is EntityType.USER
    assert event.primary_entity.username == "svc-test"
    assert event.related_entities[0].hostname == "SRV-TEST-0042"


def test_uses_target_ip_when_hostname_is_absent() -> None:
    event = JumpServerCollector().process(
        {
            "event_type": "session_started",
            "username": "operator-test",
            "timestamp": "2026-07-10T09:30:00+00:00",
            "target_ip": "10.20.30.40",
        }
    )
    assert event.related_entities[0].entity_type is EntityType.IP_ADDRESS
    assert event.related_entities[0].ip_address == "10.20.30.40"


async def test_poll_processes_api_list() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["since"] == "2026-07-10T09:00:00+00:00"
        return httpx.Response(
            200,
            json=[
                {
                    "event_type": "session_started",
                    "username": "svc-test",
                    "timestamp": "2026-07-10T09:30:00Z",
                }
            ],
        )

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="https://jump.example.test"
    ) as client:
        events = await JumpServerCollector().poll(client, datetime(2026, 7, 10, 9, tzinfo=UTC))

    assert [event.event_type for event in events] == [NormalizedEventType.SESSION_STARTED]


def test_rejects_unrecognized_event() -> None:
    with pytest.raises(ValueError, match="Unrecognized JumpServer"):
        JumpServerCollector().process(
            {
                "event_type": "unknown",
                "username": "svc-test",
                "timestamp": "2026-07-10T09:30:00Z",
            }
        )
