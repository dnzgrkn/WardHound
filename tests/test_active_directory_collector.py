from __future__ import annotations

import pytest

from app.collectors.active_directory import ActiveDirectoryCollector
from app.schemas.events import EntityType, NormalizedEventType


@pytest.mark.parametrize(
    ("event_id", "expected", "username_field"),
    [
        (4625, NormalizedEventType.AUTH_FAILED, "TargetUserName"),
        (4740, NormalizedEventType.ACCOUNT_LOCKED_OUT, "TargetUserName"),
        (4728, NormalizedEventType.GROUP_MEMBERSHIP_CHANGED, "MemberName"),
    ],
)
def test_normalizes_supported_event_ids(
    event_id: int, expected: NormalizedEventType, username_field: str
) -> None:
    payload: dict[str, object] = {
        "EventID": event_id,
        "Computer": "DC-TEST-01.example.test",
        "TimeCreated": "2026-07-10T09:30:00Z",
        "TargetDomainName": "CORP",
        username_field: "svc-test",
    }

    event = ActiveDirectoryCollector().process(payload)

    assert event.event_type is expected
    assert event.primary_entity.entity_type is EntityType.USER
    assert event.primary_entity.username == "svc-test"
    assert event.primary_entity.domain == "CORP"
    assert event.extra_attributes["EventID"] == event_id


def test_rejects_unsupported_event_id() -> None:
    with pytest.raises(ValueError, match="Unsupported Active Directory EventID"):
        ActiveDirectoryCollector().process(
            {
                "EventID": 9999,
                "Computer": "DC-TEST-01.example.test",
                "TimeCreated": "2026-07-10T09:30:00Z",
                "TargetUserName": "svc-test",
            }
        )


def test_rejects_malformed_event() -> None:
    with pytest.raises(ValueError, match="numeric EventID"):
        ActiveDirectoryCollector().process({"Computer": "DC-TEST-01.example.test"})
