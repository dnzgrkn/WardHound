"""
Unit tests for app/collectors/base.py.

Uses a DummyCollector (concrete subclass) to verify the BaseCollector contract
without any real network transport. Tests confirm that parse_raw() and normalize()
are called in the right order by process(), that abstract methods cannot be
omitted, and that subclasses correctly implement the interface.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.collectors.base import BaseCollector
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
# DummyCollector — minimal concrete implementation for testing the contract
# ---------------------------------------------------------------------------

class DummyCollector(BaseCollector):
    """
    Synthetic PacketFence-like collector.

    Accepts a dict payload with keys:
      - "mac": MAC address string
      - "event": one of "auth_failed", "device_registered", "device_quarantined"
      - "host": source host FQDN (optional, defaults to a generic value)

    Severity is hardcoded to MEDIUM for simplicity.
    """

    _SOURCE_HOST_DEFAULT = "nac-generic-01.example.internal"

    @property
    def source_system(self) -> SourceSystem:
        return SourceSystem.PACKETFENCE

    def parse_raw(self, data: bytes | str | dict[str, Any]) -> RawEvent:
        if isinstance(data, bytes):
            import json
            payload: dict[str, Any] = json.loads(data.decode())
        elif isinstance(data, str):
            import json
            payload = json.loads(data)
        elif isinstance(data, dict):
            payload = data
        else:
            raise ValueError(f"Unsupported data type: {type(data)}")

        return RawEvent(
            source_system=self.source_system,
            source_host=payload.get("host", self._SOURCE_HOST_DEFAULT),
            raw_payload=payload,
        )

    def normalize(self, event: RawEvent) -> NormalizedEvent:
        if not isinstance(event.raw_payload, dict):
            raise ValueError("DummyCollector expects a dict payload")

        payload = event.raw_payload
        event_str = payload.get("event", "")

        event_type_map: dict[str, NormalizedEventType] = {
            "auth_failed": NormalizedEventType.AUTH_FAILED,
            "device_registered": NormalizedEventType.DEVICE_REGISTERED,
            "device_quarantined": NormalizedEventType.DEVICE_QUARANTINED,
        }

        event_type = event_type_map.get(event_str)
        if event_type is None:
            raise ValueError(f"Unknown event type for DummyCollector: {event_str!r}")

        mac = payload.get("mac")
        if not mac:
            raise ValueError("DummyCollector requires 'mac' in payload")

        return NormalizedEvent(
            raw_event_id=event.id,
            source_system=self.source_system,
            event_type=event_type,
            severity=Severity.MEDIUM,
            primary_entity=NormalizedEntity(
                entity_type=EntityType.DEVICE,
                mac_address=mac,
            ),
            occurred_at=event.received_at,
        )


# ---------------------------------------------------------------------------
# Abstract enforcement
# ---------------------------------------------------------------------------


def test_cannot_instantiate_base_collector_directly() -> None:
    with pytest.raises(TypeError, match="abstract"):
        BaseCollector()  # type: ignore[abstract]


def test_partial_subclass_missing_normalize_is_abstract() -> None:
    class PartialCollector(BaseCollector):
        @property
        def source_system(self) -> SourceSystem:
            return SourceSystem.JUMPSERVER

        def parse_raw(self, data: bytes | str | dict[str, Any]) -> RawEvent:
            return RawEvent(
                source_system=self.source_system,
                source_host="js-01.example.internal",
                raw_payload=data if isinstance(data, dict) else {},
            )

    with pytest.raises(TypeError, match="abstract"):
        PartialCollector()  # type: ignore[abstract]


# ---------------------------------------------------------------------------
# DummyCollector — parse_raw
# ---------------------------------------------------------------------------


def test_parse_raw_from_dict() -> None:
    collector = DummyCollector()
    raw = collector.parse_raw({"mac": "aa:bb:cc:dd:ee:ff", "event": "auth_failed"})
    assert raw.source_system == SourceSystem.PACKETFENCE
    assert isinstance(raw.raw_payload, dict)


def test_parse_raw_from_json_string() -> None:
    collector = DummyCollector()
    import json
    data = json.dumps({"mac": "aa:bb:cc:dd:ee:ff", "event": "auth_failed"})
    raw = collector.parse_raw(data)
    assert raw.source_system == SourceSystem.PACKETFENCE


def test_parse_raw_from_json_bytes() -> None:
    collector = DummyCollector()
    import json
    data = json.dumps({"mac": "aa:bb:cc:dd:ee:ff", "event": "auth_failed"}).encode()
    raw = collector.parse_raw(data)
    assert isinstance(raw.raw_payload, dict)


def test_parse_raw_uses_host_from_payload() -> None:
    collector = DummyCollector()
    raw = collector.parse_raw(
        {"mac": "aa:bb:cc:dd:ee:ff", "event": "auth_failed", "host": "nac-42.example.internal"}
    )
    assert raw.source_host == "nac-42.example.internal"


def test_parse_raw_uses_default_host_when_absent() -> None:
    collector = DummyCollector()
    raw = collector.parse_raw({"mac": "aa:bb:cc:dd:ee:ff", "event": "auth_failed"})
    assert raw.source_host == DummyCollector._SOURCE_HOST_DEFAULT


# ---------------------------------------------------------------------------
# DummyCollector — normalize
# ---------------------------------------------------------------------------


def test_normalize_auth_failed() -> None:
    collector = DummyCollector()
    raw = collector.parse_raw({"mac": "aa:bb:cc:dd:ee:ff", "event": "auth_failed"})
    norm = collector.normalize(raw)
    assert norm.event_type == NormalizedEventType.AUTH_FAILED
    assert norm.source_system == SourceSystem.PACKETFENCE
    assert norm.primary_entity.mac_address == "aa:bb:cc:dd:ee:ff"
    assert norm.raw_event_id == raw.id


def test_normalize_device_registered() -> None:
    collector = DummyCollector()
    raw = collector.parse_raw({"mac": "11:22:33:44:55:66", "event": "device_registered"})
    norm = collector.normalize(raw)
    assert norm.event_type == NormalizedEventType.DEVICE_REGISTERED


def test_normalize_device_quarantined() -> None:
    collector = DummyCollector()
    raw = collector.parse_raw({"mac": "11:22:33:44:55:66", "event": "device_quarantined"})
    norm = collector.normalize(raw)
    assert norm.event_type == NormalizedEventType.DEVICE_QUARANTINED
    assert norm.severity == Severity.MEDIUM


def test_normalize_unknown_event_raises() -> None:
    collector = DummyCollector()
    raw = collector.parse_raw({"mac": "aa:bb:cc:dd:ee:ff", "event": "port_scan"})
    with pytest.raises(ValueError, match="Unknown event type"):
        collector.normalize(raw)


def test_normalize_missing_mac_raises() -> None:
    collector = DummyCollector()
    raw = collector.parse_raw({"event": "auth_failed"})
    with pytest.raises(ValueError, match="mac"):
        collector.normalize(raw)


def test_normalize_preserves_raw_event_id() -> None:
    collector = DummyCollector()
    raw = collector.parse_raw({"mac": "aa:bb:cc:dd:ee:ff", "event": "auth_failed"})
    norm = collector.normalize(raw)
    assert norm.raw_event_id == raw.id


# ---------------------------------------------------------------------------
# BaseCollector.process() — end-to-end convenience method
# ---------------------------------------------------------------------------


def test_process_end_to_end() -> None:
    collector = DummyCollector()
    norm = collector.process({"mac": "aa:bb:cc:dd:ee:ff", "event": "auth_failed"})
    assert isinstance(norm, NormalizedEvent)
    assert norm.event_type == NormalizedEventType.AUTH_FAILED


def test_process_returns_normalized_event_instance() -> None:
    collector = DummyCollector()
    result = collector.process({"mac": "cc:dd:ee:ff:00:11", "event": "device_quarantined"})
    assert isinstance(result, NormalizedEvent)
    assert result.event_type == NormalizedEventType.DEVICE_QUARANTINED


def test_source_system_property() -> None:
    collector = DummyCollector()
    assert collector.source_system == SourceSystem.PACKETFENCE
