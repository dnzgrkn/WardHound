"""PacketFence RFC5424 syslog collector."""

from __future__ import annotations

import re
import shlex
from datetime import UTC, datetime
from typing import Any

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

_RFC5424 = re.compile(
    r"^<(?P<priority>\d{1,3})>(?P<version>\d+) "
    r"(?P<timestamp>\S+) (?P<host>\S+) (?P<app>\S+) "
    r"(?P<procid>\S+) (?P<msgid>\S+) (?P<rest>.*)$"
)
_MAC = re.compile(r"^[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}$")


class PacketFenceCollector(BaseCollector):
    """Parse PacketFence events carried in RFC5424 syslog messages."""

    @property
    def source_system(self) -> SourceSystem:
        return SourceSystem.PACKETFENCE

    def parse_raw(self, data: bytes | str | dict[str, Any]) -> RawEvent:
        if isinstance(data, dict):
            raise ValueError("PacketFence input must be an RFC5424 syslog line")
        if isinstance(data, bytes):
            try:
                line = data.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError("PacketFence syslog input must be UTF-8") from exc
        else:
            line = data

        match = _RFC5424.fullmatch(line.strip())
        if match is None or match["host"] == "-":
            raise ValueError("Malformed RFC5424 PacketFence syslog line")

        rest = match["rest"]
        # Assumption pending real-log validation: PacketFence emits an optional
        # RFC5424 structured-data block followed by an event keyword and flat
        # shell-style key=value pairs (quoted values are supported).
        message = rest
        if rest.startswith("["):
            closing = rest.find("]")
            if closing < 0:
                raise ValueError("Malformed RFC5424 structured data")
            message = rest[closing + 1 :].strip()
        elif rest.startswith("-"):
            message = rest[1:].strip()

        try:
            tokens = shlex.split(message)
        except ValueError as exc:
            raise ValueError("Malformed PacketFence message content") from exc
        if not tokens:
            raise ValueError("PacketFence message content is empty")

        payload: dict[str, Any] = {
            "event": tokens[0].lower(),
            "timestamp": match["timestamp"],
            "app_name": match["app"],
        }
        for token in tokens[1:]:
            if "=" in token:
                key, value = token.split("=", 1)
                payload[key.lower()] = value

        return RawEvent(
            source_system=self.source_system,
            source_host=match["host"],
            raw_payload=payload,
        )

    def normalize(self, event: RawEvent) -> NormalizedEvent:
        payload = self._payload(event)
        event_name = str(payload.get("event", "")).lower().replace("-", "_")
        mappings = {
            "auth_failed": (NormalizedEventType.AUTH_FAILED, Severity.MEDIUM),
            "authentication_failed": (NormalizedEventType.AUTH_FAILED, Severity.MEDIUM),
            "device_unknown": (NormalizedEventType.DEVICE_UNKNOWN, Severity.MEDIUM),
            "unknown_device": (NormalizedEventType.DEVICE_UNKNOWN, Severity.MEDIUM),
            "device_registered": (NormalizedEventType.DEVICE_REGISTERED, Severity.LOW),
            "registration": (NormalizedEventType.DEVICE_REGISTERED, Severity.LOW),
            "device_quarantined": (NormalizedEventType.DEVICE_QUARANTINED, Severity.HIGH),
            "quarantine": (NormalizedEventType.DEVICE_QUARANTINED, Severity.HIGH),
            "vlan_assigned": (NormalizedEventType.VLAN_ASSIGNED, Severity.LOW),
            "vlan_assignment": (NormalizedEventType.VLAN_ASSIGNED, Severity.LOW),
        }
        if event_name not in mappings:
            raise ValueError(f"Unrecognized PacketFence event: {event_name or '<missing>'}")

        mac = payload.get("mac") or payload.get("mac_address")
        if not isinstance(mac, str) or not _MAC.fullmatch(mac):
            raise ValueError("PacketFence event requires a valid MAC address")
        occurred_at = self._parse_timestamp(payload.get("timestamp"))
        event_type, severity = mappings[event_name]
        hostname = payload.get("hostname")
        return NormalizedEvent(
            raw_event_id=event.id,
            source_system=self.source_system,
            event_type=event_type,
            severity=severity,
            primary_entity=NormalizedEntity(
                entity_type=EntityType.DEVICE,
                mac_address=mac.lower().replace("-", ":"),
                hostname=hostname if isinstance(hostname, str) else None,
            ),
            occurred_at=occurred_at,
            extra_attributes={
                key: payload[key] for key in ("ip", "role", "vlan") if key in payload
            },
        )

    @staticmethod
    def _payload(event: RawEvent) -> dict[str, Any]:
        if event.source_system is not SourceSystem.PACKETFENCE or not isinstance(
            event.raw_payload, dict
        ):
            raise ValueError("RawEvent is not a structured PacketFence event")
        return event.raw_payload

    @staticmethod
    def _parse_timestamp(value: object) -> datetime:
        if not isinstance(value, str):
            raise ValueError("PacketFence event requires a timestamp")
        if value == "-":
            raise ValueError("PacketFence event timestamp is missing")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("Invalid PacketFence timestamp") from exc
        if parsed.tzinfo is None:
            raise ValueError("PacketFence timestamp must include a timezone")
        return parsed.astimezone(UTC)
