"""
Unit tests for app/schemas/events.py.

Tests cover schema construction, field defaults, enum membership,
model_validator enforcement, and immutability. No network I/O; all data
is synthetic.
"""

from __future__ import annotations

from datetime import UTC

import pytest
from pydantic import ValidationError

from app.schemas.events import (
    EntityType,
    NormalizedEntity,
    NormalizedEvent,
    NormalizedEventType,
    RawEvent,
    Severity,
    SourceSystem,
)

# ---------------------------------------------------------------------------
# Helpers — synthetic event fixtures (genericized, no real client data)
# ---------------------------------------------------------------------------

SOURCE_HOST = "nac-01.example.internal"
USER_ENTITY = NormalizedEntity(
    entity_type=EntityType.USER,
    username="jdoe",
    domain="CORP",
)
DEVICE_ENTITY = NormalizedEntity(
    entity_type=EntityType.DEVICE,
    mac_address="aa:bb:cc:dd:ee:ff",
    hostname="ws-generic-001.example.internal",
)
IP_ENTITY = NormalizedEntity(
    entity_type=EntityType.IP_ADDRESS,
    ip_address="10.20.30.40",
)


def make_raw_event(**overrides: object) -> RawEvent:
    defaults: dict[str, object] = {
        "source_system": SourceSystem.PACKETFENCE,
        "source_host": SOURCE_HOST,
        "raw_payload": {"action": "auth_failed", "mac": "aa:bb:cc:dd:ee:ff"},
    }
    defaults.update(overrides)
    return RawEvent(**defaults)


def make_normalized_event(**overrides: object) -> NormalizedEvent:
    import uuid
    from datetime import datetime

    defaults: dict[str, object] = {
        "raw_event_id": uuid.uuid4(),
        "source_system": SourceSystem.PACKETFENCE,
        "event_type": NormalizedEventType.AUTH_FAILED,
        "severity": Severity.MEDIUM,
        "primary_entity": DEVICE_ENTITY,
        "occurred_at": datetime.now(UTC),
    }
    defaults.update(overrides)
    return NormalizedEvent(**defaults)


# ---------------------------------------------------------------------------
# SourceSystem enum
# ---------------------------------------------------------------------------


def test_source_system_values() -> None:
    assert SourceSystem.PACKETFENCE.value == "packetfence"
    assert SourceSystem.JUMPSERVER.value == "jumpserver"
    assert SourceSystem.ACTIVE_DIRECTORY.value == "active_directory"
    assert SourceSystem.FIREWALL.value == "firewall"
    # Verify string round-trip (StrEnum: the string IS the value)
    assert SourceSystem("packetfence") is SourceSystem.PACKETFENCE


# ---------------------------------------------------------------------------
# NormalizedEventType enum — spot-check coverage across all four source systems
# ---------------------------------------------------------------------------


def test_event_type_coverage_per_source() -> None:
    # NAC (PacketFence)
    assert NormalizedEventType.AUTH_FAILED.value == "auth_failed"
    assert NormalizedEventType.DEVICE_QUARANTINED.value == "device_quarantined"
    assert NormalizedEventType.VLAN_ASSIGNED.value == "vlan_assigned"

    # PAM (JumpServer)
    assert NormalizedEventType.SESSION_STARTED.value == "session_started"
    assert NormalizedEventType.PRIVILEGED_COMMAND_EXECUTED.value == "privileged_command_executed"
    assert NormalizedEventType.SESSION_ANOMALY_DETECTED.value == "session_anomaly_detected"

    # Identity (AD)
    assert NormalizedEventType.PASSWORD_SPRAY_DETECTED.value == "password_spray_detected"
    assert NormalizedEventType.GROUP_MEMBERSHIP_CHANGED.value == "group_membership_changed"
    assert NormalizedEventType.TIER_VIOLATION_DETECTED.value == "tier_violation_detected"
    assert NormalizedEventType.ACCOUNT_LOCKED_OUT.value == "account_locked_out"

    # Network (Firewall)
    assert NormalizedEventType.TRAFFIC_BLOCKED.value == "traffic_blocked"
    assert NormalizedEventType.LATERAL_MOVEMENT_ATTEMPT.value == "lateral_movement_attempt"
    assert NormalizedEventType.PORT_SCAN_DETECTED.value == "port_scan_detected"
    assert NormalizedEventType.UNEXPECTED_EAST_WEST_TRAFFIC.value == "unexpected_east_west_traffic"


# ---------------------------------------------------------------------------
# NormalizedEntity
# ---------------------------------------------------------------------------


def test_user_entity_valid() -> None:
    e = NormalizedEntity(entity_type=EntityType.USER, username="jdoe", domain="CORP")
    assert e.username == "jdoe"
    assert e.domain == "CORP"
    assert e.display_name == "CORP\\jdoe"


def test_user_entity_no_domain_display_name() -> None:
    e = NormalizedEntity(entity_type=EntityType.USER, username="svc-backup")
    assert e.display_name == "svc-backup"


def test_device_entity_valid() -> None:
    e = NormalizedEntity(
        entity_type=EntityType.DEVICE,
        mac_address="aa:bb:cc:dd:ee:ff",
        hostname="ws-generic-001.example.internal",
    )
    assert e.display_name == "ws-generic-001.example.internal"


def test_device_entity_mac_only_display_name() -> None:
    e = NormalizedEntity(entity_type=EntityType.DEVICE, mac_address="aa:bb:cc:dd:ee:ff")
    assert e.display_name == "aa:bb:cc:dd:ee:ff"


def test_ip_entity_valid() -> None:
    e = NormalizedEntity(entity_type=EntityType.IP_ADDRESS, ip_address="10.20.30.40")
    assert e.display_name == "10.20.30.40"


def test_entity_requires_at_least_one_identifier() -> None:
    with pytest.raises(ValidationError, match="at least one identifying field"):
        NormalizedEntity(entity_type=EntityType.USER)


def test_entity_type_user_with_ip_is_allowed() -> None:
    # entity_type and field population are independent — a USER entity CAN have
    # an ip_address if the source system provides it alongside the username.
    e = NormalizedEntity(
        entity_type=EntityType.USER,
        username="jdoe",
        ip_address="10.20.30.40",
    )
    assert e.username == "jdoe"
    assert e.ip_address == "10.20.30.40"


# ---------------------------------------------------------------------------
# RawEvent
# ---------------------------------------------------------------------------


def test_raw_event_defaults() -> None:
    evt = make_raw_event()
    assert evt.source_system == SourceSystem.PACKETFENCE
    assert evt.id is not None
    assert evt.received_at is not None


def test_raw_event_accepts_string_payload() -> None:
    raw_syslog = "<13>Jul 10 12:34:56 nac-01 packetfence: auth_failed mac=aa:bb:cc"
    evt = make_raw_event(raw_payload=raw_syslog)
    assert evt.raw_payload == raw_syslog


def test_raw_event_accepts_dict_payload() -> None:
    payload = {"event": "registration", "mac": "aa:bb:cc:dd:ee:ff", "role": "guest"}
    evt = make_raw_event(raw_payload=payload)
    assert isinstance(evt.raw_payload, dict)


def test_raw_event_is_immutable() -> None:
    evt = make_raw_event()
    with pytest.raises(ValidationError):
        evt.source_host = "tampered-host"  # type: ignore[misc]


def test_raw_event_requires_source_host() -> None:
    with pytest.raises(ValidationError):
        make_raw_event(source_host="")


def test_raw_event_unique_ids() -> None:
    e1 = make_raw_event()
    e2 = make_raw_event()
    assert e1.id != e2.id


# ---------------------------------------------------------------------------
# NormalizedEvent
# ---------------------------------------------------------------------------


def test_normalized_event_valid() -> None:
    evt = make_normalized_event()
    assert evt.event_type == NormalizedEventType.AUTH_FAILED
    assert evt.severity == Severity.MEDIUM
    assert evt.primary_entity.entity_type == EntityType.DEVICE


def test_normalized_event_with_related_entities() -> None:
    evt = make_normalized_event(
        primary_entity=USER_ENTITY,
        related_entities=[DEVICE_ENTITY, IP_ENTITY],
    )
    assert len(evt.related_entities) == 2
    assert evt.related_entities[0].mac_address == "aa:bb:cc:dd:ee:ff"


def test_normalized_event_empty_related_entities_by_default() -> None:
    evt = make_normalized_event()
    assert evt.related_entities == []


def test_normalized_event_extra_attributes() -> None:
    evt = make_normalized_event(
        extra_attributes={"ad_event_id": 4625, "logon_type": 3},
    )
    assert evt.extra_attributes["ad_event_id"] == 4625


def test_normalized_event_is_immutable() -> None:
    evt = make_normalized_event()
    with pytest.raises(ValidationError):
        evt.severity = Severity.CRITICAL  # type: ignore[misc]


def test_normalized_event_unique_ids() -> None:
    e1 = make_normalized_event()
    e2 = make_normalized_event()
    assert e1.id != e2.id


def test_normalized_event_ad_auth_failed() -> None:
    """Verify an AD auth failure can be constructed correctly."""
    import uuid
    from datetime import datetime

    evt = NormalizedEvent(
        raw_event_id=uuid.uuid4(),
        source_system=SourceSystem.ACTIVE_DIRECTORY,
        event_type=NormalizedEventType.AUTH_FAILED,
        severity=Severity.MEDIUM,
        primary_entity=NormalizedEntity(
            entity_type=EntityType.USER,
            username="jdoe",
            domain="CORP",
        ),
        related_entities=[
            NormalizedEntity(
                entity_type=EntityType.DEVICE,
                hostname="dc-01.example.internal",
            )
        ],
        occurred_at=datetime.now(UTC),
        extra_attributes={"ad_event_id": 4625, "logon_type": 3},
    )
    assert evt.source_system == SourceSystem.ACTIVE_DIRECTORY
    assert evt.extra_attributes["ad_event_id"] == 4625


def test_normalized_event_firewall_lateral_movement() -> None:
    """Verify a firewall lateral movement event can be constructed."""
    import uuid
    from datetime import datetime

    src = NormalizedEntity(entity_type=EntityType.IP_ADDRESS, ip_address="10.20.1.50")
    dst = NormalizedEntity(entity_type=EntityType.IP_ADDRESS, ip_address="10.20.2.100")

    evt = NormalizedEvent(
        raw_event_id=uuid.uuid4(),
        source_system=SourceSystem.FIREWALL,
        event_type=NormalizedEventType.LATERAL_MOVEMENT_ATTEMPT,
        severity=Severity.HIGH,
        primary_entity=src,
        related_entities=[dst],
        occurred_at=datetime.now(UTC),
        extra_attributes={"rule_name": "deny-east-west", "dest_port": 445},
    )
    assert evt.severity == Severity.HIGH
    assert evt.related_entities[0].ip_address == "10.20.2.100"
