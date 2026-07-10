from __future__ import annotations

import pytest

from app.collectors.packetfence import PacketFenceCollector
from app.schemas.events import EntityType, NormalizedEventType, SourceSystem


@pytest.mark.parametrize(
    ("keyword", "expected"),
    [
        ("auth_failed", NormalizedEventType.AUTH_FAILED),
        ("device_unknown", NormalizedEventType.DEVICE_UNKNOWN),
        ("device_registered", NormalizedEventType.DEVICE_REGISTERED),
        ("device_quarantined", NormalizedEventType.DEVICE_QUARANTINED),
        ("vlan_assigned", NormalizedEventType.VLAN_ASSIGNED),
    ],
)
def test_normalizes_supported_event_types(keyword: str, expected: NormalizedEventType) -> None:
    line = (
        f"<134>1 2026-07-10T09:30:00Z pf-01.example.test packetfence 42 NAC001 - "
        f"{keyword} mac=02:00:00:00:00:42 ip=10.20.30.40 "
        'hostname=WKSTN-0042 role="test role" vlan=120'
    )

    event = PacketFenceCollector().process(line.encode())

    assert event.source_system is SourceSystem.PACKETFENCE
    assert event.event_type is expected
    assert event.primary_entity.entity_type is EntityType.DEVICE
    assert event.primary_entity.mac_address == "02:00:00:00:00:42"
    assert event.primary_entity.hostname == "WKSTN-0042"
    assert event.extra_attributes["vlan"] == "120"


def test_rejects_malformed_syslog() -> None:
    with pytest.raises(ValueError, match="Malformed RFC5424"):
        PacketFenceCollector().process("not syslog")


def test_rejects_unrecognized_event() -> None:
    line = (
        "<134>1 2026-07-10T09:30:00Z pf-01.example.test packetfence 42 NAC001 - "
        "unexpected_event mac=02:00:00:00:00:42"
    )
    with pytest.raises(ValueError, match="Unrecognized PacketFence"):
        PacketFenceCollector().process(line)
