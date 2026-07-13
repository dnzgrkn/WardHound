from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest

from app.collectors.packetfence import PacketFenceCollector
from app.schemas.events import EntityType, NormalizedEventType, Severity, SourceSystem


@pytest.mark.parametrize(
    ("message", "expected", "reason"),
    [
        (
            "(189650)   Login OK: [CORP\\jdoe] (from client SW-Access-01 port 65551 "
            "cli AA:BB:CC:DD:EE:FF via TLS tunnel)",
            NormalizedEventType.AUTH_SUCCEEDED,
            None,
        ),
        (
            "(530) Login incorrect (mschap: Program returned code (5) and output ''): "
            "[CORP\\jdoe] (from client SW-Access-01 port 65551 cli AA:BB:CC:DD:EE:FF)",
            NormalizedEventType.AUTH_FAILED,
            "mschap: Program returned code (5) and output ''",
        ),
    ],
)
def test_normalizes_radius_auth(
    message: str, expected: NormalizedEventType, reason: str | None
) -> None:
    line = f"2026-07-09T15:47:10.550655+03:00 packetfence auth[6092]: {message}"

    event = PacketFenceCollector().process(line.encode())

    assert event.source_system is SourceSystem.PACKETFENCE
    assert event.event_type is expected
    assert event.primary_entity.entity_type is EntityType.DEVICE
    assert event.primary_entity.mac_address == "aa:bb:cc:dd:ee:ff"
    assert event.related_entities[0].username == "jdoe"
    assert event.related_entities[0].domain == "CORP"
    assert event.extra_attributes.get("reason") == reason


def test_correlates_vlan_assignment_lines() -> None:
    context = (
        "2026-07-07T02:23:37.770855+03:00 packetfence httpd.aaa-docker-wrapper[909654]: "
        'httpd.aaa(7) INFO: [mac:AA:BB:CC:DD:EE:FF] PID: "jdoe", Status: reg '
        "Returned VLAN: (undefined), Role: Accounting (pf::role::fetchRoleForNode)"
    )
    assignment = (
        "2026-07-07T02:23:37.775741+03:00 packetfence httpd.aaa-docker-wrapper[909654]: "
        "httpd.aaa(7) INFO: [mac:AA:BB:CC:DD:EE:FF] (10.20.30.2) Added VLAN 45 "
        "to the returned RADIUS Access-Accept (pf::Switch::Template::returnRadiusAccessAccept)"
    )

    event = PacketFenceCollector().process_vlan_pair(context, assignment)

    assert event.event_type is NormalizedEventType.VLAN_ASSIGNED
    assert event.extra_attributes["vlan"] == "45"
    assert event.extra_attributes["role"] == "Accounting"
    assert event.related_entities[0].username == "jdoe"


async def test_node_status_poller_diffs_snapshots() -> None:
    responses = iter(
        [
            [{"mac": "AA:BB:CC:DD:EE:01", "status": "unreg", "category": ""}],
            [{"mac": "AA:BB:CC:DD:EE:01", "status": "reg", "category": "Accounting"}],
            [{"mac": "AA:BB:CC:DD:EE:01", "status": "reg", "category": "Isolation"}],
        ]
    )

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/nodes"
        return httpx.Response(200, json=next(responses))

    collector = PacketFenceCollector()
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="https://packetfence.example.test"
    ) as client:
        first = await collector.poll_node_status(client)
        second = await collector.poll_node_status(client)
        third = await collector.poll_node_status(client)

    assert first[0].event_type is NormalizedEventType.DEVICE_UNKNOWN
    assert second[0].event_type is NormalizedEventType.DEVICE_REGISTERED
    assert third[0].event_type is NormalizedEventType.DEVICE_QUARANTINED
    assert third[0].severity is Severity.HIGH
    assert first[0].occurred_at.tzinfo is UTC


@pytest.mark.parametrize(
    ("line", "message"),
    [
        ("not syslog", "Malformed PacketFence"),
        (
            "2026-07-09T15:47:10+03:00 packetfence auth[1]: unsupported message",
            "Unrecognized PacketFence",
        ),
        (
            "2026-07-09T15:47:10+03:00 packetfence auth[1]: (1) Login OK: "
            "[CORP\\jdoe] (from client SW-Access-01 port 1 cli not-a-mac)",
            "valid colon-separated MAC",
        ),
    ],
)
def test_rejects_malformed_log(line: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        PacketFenceCollector().process(line)


def test_rejects_mismatched_vlan_pair() -> None:
    context = (
        "2026-07-07T02:23:37+03:00 packetfence httpd.aaa-docker-wrapper[1]: "
        'httpd.aaa(7) INFO: [mac:AA:BB:CC:DD:EE:01] PID: "jdoe", Status: reg '
        "Returned VLAN: (undefined), Role: Accounting (pf::role::fetchRoleForNode)"
    )
    assignment = (
        "2026-07-07T02:23:38+03:00 packetfence httpd.aaa-docker-wrapper[1]: "
        "httpd.aaa(7) INFO: [mac:AA:BB:CC:DD:EE:02] (10.20.30.2) Added VLAN 45 "
        "to the returned RADIUS Access-Accept (pf::Switch::Template::returnRadiusAccessAccept)"
    )
    with pytest.raises(ValueError, match="same device"):
        PacketFenceCollector().process_vlan_pair(context, assignment)


def test_rejects_vlan_assignment_without_context() -> None:
    assignment = (
        "2026-07-07T02:23:38+03:00 packetfence httpd.aaa-docker-wrapper[1]: "
        "httpd.aaa(7) INFO: [mac:AA:BB:CC:DD:EE:02] (10.20.30.2) Added VLAN 45 "
        "to the returned RADIUS Access-Accept (pf::Switch::Template::returnRadiusAccessAccept)"
    )
    with pytest.raises(ValueError, match="correlated context"):
        PacketFenceCollector().process(assignment)


def test_node_timestamp_uses_received_time_when_detect_date_is_absent() -> None:
    event = PacketFenceCollector().process(
        {
            "kind": "node_state",
            "event_type": "device_unknown",
            "source_host": "packetfence.local",
            "mac": "AA:BB:CC:DD:EE:01",
            "status": "unreg",
            "category": "",
        }
    )
    assert event.occurred_at <= datetime.now(UTC)
