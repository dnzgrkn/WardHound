from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest

from app.collectors.jumpserver import JumpServerCollector
from app.schemas.events import EntityType, NormalizedEventType, Severity


def login_record(username: str, status: bool = True) -> dict[str, object]:
    return {
        "id": "f1786d27-4e5c-4014-b4a3-21ffaf666f0c",
        "username": username,
        "type": {"value": "W", "label": "Web"},
        "ip": "10.20.30.40",
        "mfa": {"value": 1, "label": "Enabled"},
        "reason": "" if status else "The supplied credentials were rejected",
        "reason_display": "" if status else "The supplied credentials were rejected",
        "backend": "Password" if status else "",
        "status": {"value": status, "label": "Success" if status else "Failed"},
        "datetime": "2026/07/13 10:52:58 +0300",
    }


@pytest.mark.parametrize(
    ("username", "status", "expected", "login_id"),
    [
        ("Jane Doe(jdoe)", True, NormalizedEventType.AUTH_SUCCEEDED, "jdoe"),
        ("jdoe", False, NormalizedEventType.AUTH_FAILED, "jdoe"),
    ],
)
def test_normalizes_login_logs(
    username: str, status: bool, expected: NormalizedEventType, login_id: str
) -> None:
    event = JumpServerCollector().process(login_record(username, status))

    assert event.event_type is expected
    assert event.primary_entity.username == login_id
    assert event.related_entities[0].ip_address == "10.20.30.40"
    assert event.occurred_at == datetime(2026, 7, 13, 7, 52, 58, tzinfo=UTC)


@pytest.mark.parametrize(
    ("finished", "expected"),
    [
        (False, NormalizedEventType.SESSION_STARTED),
        (True, NormalizedEventType.SESSION_ENDED),
    ],
)
def test_normalizes_sessions(finished: bool, expected: NormalizedEventType) -> None:
    event = JumpServerCollector().process(
        {
            "id": "session-fake-42",
            "user": "jdoe",
            "user_id": "user-fake-42",
            "asset": "SRV-TEST-0042",
            "asset_id": "asset-fake-42",
            "account": "svc-admin",
            "account_id": "account-fake-42",
            "date_start": "2026-07-13T11:10:16.222541Z",
            "date_end": "2026-07-13T11:20:16.222541Z" if finished else None,
            "is_finished": finished,
            "login_from": {"value": "ST", "label": "SSH Terminal"},
            "is_success": True,
            "command_amount": 4,
            "protocol": "ssh",
            "remote_addr": "10.20.30.40",
        }
    )
    assert event.event_type is expected
    assert event.primary_entity.entity_type is EntityType.USER
    assert event.related_entities[0].hostname == "SRV-TEST-0042"
    assert event.extra_attributes["account"] == "svc-admin"


@pytest.mark.parametrize(
    ("risk", "expected_type", "expected_severity"),
    [
        (0, NormalizedEventType.PRIVILEGED_COMMAND_EXECUTED, Severity.LOW),
        (7, NormalizedEventType.PRIVILEGED_COMMAND_EXECUTED, Severity.MEDIUM),
        (4, NormalizedEventType.PRIVILEGED_COMMAND_EXECUTED, Severity.HIGH),
        (8, NormalizedEventType.PRIVILEGED_COMMAND_EXECUTED, Severity.HIGH),
        (5, NormalizedEventType.SESSION_ANOMALY_DETECTED, Severity.HIGH),
        (6, NormalizedEventType.SESSION_ANOMALY_DETECTED, Severity.CRITICAL),
    ],
)
def test_maps_command_risk(
    risk: int, expected_type: NormalizedEventType, expected_severity: Severity
) -> None:
    event = JumpServerCollector().process(
        {
            "user": "jdoe",
            "account": "svc-admin",
            "asset": "SRV-TEST-0042",
            "input": "synthetic-command --check",
            "output": "c3ludGhldGljLW91dHB1dA==",
            "session": "session-fake-42",
            "timestamp": 1783929600,
            "risk_level": {"value": risk, "label": "Synthetic verdict"},
            "remote_addr": "10.20.30.40",
        }
    )
    assert event.event_type is expected_type
    assert event.severity is expected_severity
    assert event.extra_attributes["output"] == "c3ludGhldGljLW91dHB1dA=="


async def test_poll_handles_envelopes_filters_and_session_transitions() -> None:
    session_finished = False

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/audits/login-logs/":
            assert "date_from" in request.url.params
            results = [login_record("Jane Doe(jdoe)")]
        elif request.url.path == "/api/v1/terminal/sessions/":
            assert request.url.params["date_start_from"] == "2026-07-10T09:00:00Z"
            results = [
                {
                    "id": "session-fake-42",
                    "user": "jdoe",
                    "asset": "SRV-TEST-0042",
                    "date_start": "2026-07-10T09:30:00Z",
                    "date_end": "2026-07-10T10:00:00Z" if session_finished else None,
                    "is_finished": session_finished,
                }
            ]
        else:
            assert request.url.params["timestamp_from"] == "1783674000"
            results = []
        return httpx.Response(
            200, json={"count": len(results), "next": None, "previous": None, "results": results}
        )

    collector = JumpServerCollector()
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="https://jump.example.test"
    ) as client:
        first = await collector.poll(client, datetime(2026, 7, 10, 9, tzinfo=UTC))
        session_finished = True
        second = await collector.poll(client, datetime(2026, 7, 10, 9, tzinfo=UTC))

    assert [event.event_type for event in first] == [
        NormalizedEventType.AUTH_SUCCEEDED,
        NormalizedEventType.SESSION_STARTED,
    ]
    assert [event.event_type for event in second] == [
        NormalizedEventType.AUTH_SUCCEEDED,
        NormalizedEventType.SESSION_ENDED,
    ]


@pytest.mark.parametrize(
    ("record", "message"),
    [
        ({"username": "jdoe"}, "Unrecognized JumpServer record shape"),
        (
            {
                **login_record("jdoe"),
                "status": {"value": "failed", "label": "Failed"},
            },
            "status.value must be a boolean",
        ),
        (
            {
                "user": "jdoe",
                "asset": "SRV-TEST-0042",
                "input": "synthetic-command",
                "timestamp": "2026-07-13T00:00:00Z",
                "risk_level": {"value": 0, "label": "Accept"},
            },
            "integer Unix epoch",
        ),
    ],
)
def test_rejects_malformed_records(record: dict[str, object], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        JumpServerCollector().process(record)


async def test_poll_rejects_bare_list_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[])

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="https://jump.example.test"
    ) as client:
        with pytest.raises(ValueError, match="paginated results envelope"):
            await JumpServerCollector().poll(client, datetime(2026, 7, 10, tzinfo=UTC))
