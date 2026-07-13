"""PacketFence RFC3164-style log and node-status collector."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

import httpx

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

_SYSLOG = re.compile(
    r"^(?P<timestamp>\S+) (?P<host>\S+) (?P<tag>[^\s:\[]+)(?:\[(?P<process_id>\d+)\])?: "
    r"(?P<message>.+)$"
)
_AUTH = re.compile(
    r"^\((?P<request_id>\d+)\)\s+"
    r"(?P<result>Login OK|Login incorrect(?: \((?P<reason>.*?)\))?): "
    r"\[(?P<domain>[^\\\]]+)\\(?P<username>[^\]]+)\] "
    r"\(from client (?P<switch>\S+) port (?P<port>\S+) cli (?P<mac>\S+)"
    r"(?: via TLS tunnel)?\)$"
)
_VLAN_CONTEXT = re.compile(
    r'^httpd\.aaa\(\d+\) INFO: \[mac:(?P<mac>[^\]]+)\] PID: "(?P<username>[^"]+)", '
    r"Status: (?P<status>reg|unreg) Returned VLAN: \((?P<returned_vlan>[^)]+)\), "
    r"Role: (?P<role>.+?) \(.+\)$"
)
_VLAN_ASSIGNMENT = re.compile(
    r"^httpd\.aaa\(\d+\) INFO: \[mac:(?P<mac>[^\]]+)\] \((?P<switch_ip>[^)]+)\) "
    r"Added VLAN (?P<vlan>\d+) to the returned RADIUS Access-Accept \(.+\)$"
)
_MAC = re.compile(r"^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$")


class PacketFenceCollector(BaseCollector):
    """Normalize PacketFence authentication, VLAN, and polled node-state events."""

    def __init__(self, node_api_url: str = "/api/v1/nodes") -> None:
        self.node_api_url = node_api_url
        self._node_states: dict[str, tuple[str, str]] = {}

    @property
    def source_system(self) -> SourceSystem:
        return SourceSystem.PACKETFENCE

    def parse_raw(self, data: bytes | str | dict[str, Any]) -> RawEvent:
        if isinstance(data, dict):
            return self._parse_node(data)
        if isinstance(data, bytes):
            try:
                line = data.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError("PacketFence log input must be UTF-8") from exc
        else:
            line = data

        match = _SYSLOG.fullmatch(line.strip())
        if match is None:
            raise ValueError("Malformed PacketFence RFC3164-style log line")
        timestamp = self._parse_timestamp(match["timestamp"])
        message = match["message"]
        payload: dict[str, Any] = {
            "timestamp": timestamp.isoformat(),
            "tag": match["tag"],
            "process_id": match["process_id"],
        }

        auth = _AUTH.fullmatch(message)
        context = _VLAN_CONTEXT.fullmatch(message)
        assignment = _VLAN_ASSIGNMENT.fullmatch(message)
        if match["tag"] == "auth" and auth is not None:
            payload.update(auth.groupdict())
            payload["kind"] = "auth"
        elif context is not None:
            payload.update(context.groupdict())
            payload["kind"] = "vlan_context"
        elif assignment is not None:
            payload.update(assignment.groupdict())
            payload["kind"] = "vlan_assignment"
        else:
            raise ValueError("Unrecognized PacketFence log message")

        self._require_mac(payload.get("mac"))
        return RawEvent(
            source_system=self.source_system,
            source_host=match["host"],
            raw_payload=payload,
        )

    def normalize(self, event: RawEvent) -> NormalizedEvent:
        payload = self._payload(event)
        kind = payload.get("kind")
        if kind == "auth":
            return self._normalize_auth(event, payload)
        if kind == "vlan_assignment":
            return self._normalize_vlan(event, payload)
        if kind == "node_state":
            event_name = payload.get("event_type")
            mappings = {
                "device_unknown": (NormalizedEventType.DEVICE_UNKNOWN, Severity.MEDIUM),
                "device_registered": (NormalizedEventType.DEVICE_REGISTERED, Severity.LOW),
                "device_quarantined": (NormalizedEventType.DEVICE_QUARANTINED, Severity.HIGH),
            }
            if event_name not in mappings:
                raise ValueError("PacketFence node state requires a recognized transition")
            event_type, severity = mappings[str(event_name)]
            return self._build_device_event(event, payload, event_type, severity)
        if kind == "vlan_context":
            raise ValueError("PacketFence VLAN context line requires its assignment line")
        raise ValueError("Unrecognized PacketFence event")

    def process_vlan_pair(
        self, context_line: bytes | str, assignment_line: bytes | str
    ) -> NormalizedEvent:
        """Correlate the two ``httpd.aaa`` lines that describe one VLAN assignment."""
        context = self.parse_raw(context_line)
        assignment = self.parse_raw(assignment_line)
        context_payload = self._payload(context)
        assignment_payload = self._payload(assignment)
        if (
            context_payload.get("kind") != "vlan_context"
            or assignment_payload.get("kind") != "vlan_assignment"
        ):
            raise ValueError("PacketFence VLAN pair must contain context then assignment lines")
        if (
            context.source_host != assignment.source_host
            or context_payload["mac"] != assignment_payload["mac"]
        ):
            raise ValueError("PacketFence VLAN lines do not identify the same device")
        context_time = self._parse_timestamp(context_payload.get("timestamp"))
        assignment_time = self._parse_timestamp(assignment_payload.get("timestamp"))
        if abs((assignment_time - context_time).total_seconds()) > 5:
            raise ValueError("PacketFence VLAN lines are outside the request window")
        merged = dict(assignment_payload)
        merged.update(
            {key: context_payload[key] for key in ("username", "status", "returned_vlan", "role")}
        )
        correlated = assignment.model_copy(update={"raw_payload": merged})
        return self.normalize(correlated)

    async def poll_node_status(
        self, client: httpx.AsyncClient, *, source_host: str = "packetfence.local"
    ) -> list[NormalizedEvent]:
        """Snapshot PacketFence nodes through REST and emit changes since the prior poll."""
        response = await client.get(self.node_api_url)
        response.raise_for_status()
        body = response.json()
        records = body.get("items") if isinstance(body, dict) else body
        if not isinstance(records, list) or not all(isinstance(item, dict) for item in records):
            raise ValueError("PacketFence node API response must contain a list of objects")
        events: list[NormalizedEvent] = []
        for record in records:
            for transition in self._node_transitions(record):
                enriched = dict(record)
                enriched.update(
                    {"kind": "node_state", "event_type": transition, "source_host": source_host}
                )
                events.append(self.process(enriched))
        return events

    def _node_transitions(self, node: dict[str, Any]) -> list[str]:
        mac = self._require_mac(node.get("mac"))
        status = node.get("status")
        category = node.get("category") or ""
        if status not in ("reg", "unreg") or not isinstance(category, str):
            raise ValueError("PacketFence node requires status reg/unreg and a string category")
        previous = self._node_states.get(mac)
        self._node_states[mac] = (status, category)
        if previous is None:
            return ["device_unknown"]
        transitions: list[str] = []
        if previous[0] == "unreg" and status == "reg":
            transitions.append("device_registered")
        if previous[1] != category and self._is_isolation_role(category):
            transitions.append("device_quarantined")
        return transitions

    def _parse_node(self, data: dict[str, Any]) -> RawEvent:
        if data.get("kind") != "node_state":
            raise ValueError("PacketFence object input must be a node-state transition")
        source_host = data.get("source_host")
        if not isinstance(source_host, str) or not source_host:
            raise ValueError("PacketFence node state requires source_host")
        self._require_mac(data.get("mac"))
        return RawEvent(
            source_system=self.source_system, source_host=source_host, raw_payload=dict(data)
        )

    def _normalize_auth(self, event: RawEvent, payload: dict[str, Any]) -> NormalizedEvent:
        result = payload.get("result")
        if not isinstance(result, str):
            raise ValueError("PacketFence auth event requires a result")
        succeeded = result == "Login OK"
        username = payload.get("username")
        domain = payload.get("domain")
        related = []
        if isinstance(username, str) and username:
            related.append(
                NormalizedEntity(
                    entity_type=EntityType.USER,
                    username=username,
                    domain=domain if isinstance(domain, str) else None,
                )
            )
        return NormalizedEvent(
            raw_event_id=event.id,
            source_system=self.source_system,
            event_type=(
                NormalizedEventType.AUTH_SUCCEEDED if succeeded else NormalizedEventType.AUTH_FAILED
            ),
            severity=Severity.LOW if succeeded else Severity.MEDIUM,
            primary_entity=NormalizedEntity(
                entity_type=EntityType.DEVICE, mac_address=str(payload["mac"]).lower()
            ),
            related_entities=related,
            occurred_at=self._parse_timestamp(payload.get("timestamp")),
            extra_attributes={
                key: payload[key]
                for key in ("reason", "request_id", "switch", "port")
                if payload.get(key) is not None
            },
        )

    def _normalize_vlan(self, event: RawEvent, payload: dict[str, Any]) -> NormalizedEvent:
        if any(key not in payload for key in ("username", "status", "role")):
            raise ValueError("PacketFence VLAN assignment requires its correlated context line")
        normalized = self._build_device_event(
            event, payload, NormalizedEventType.VLAN_ASSIGNED, Severity.LOW
        )
        username = payload.get("username")
        if isinstance(username, str) and username and username != "default":
            return normalized.model_copy(
                update={
                    "related_entities": [
                        NormalizedEntity(entity_type=EntityType.USER, username=username)
                    ]
                }
            )
        return normalized

    def _build_device_event(
        self,
        event: RawEvent,
        payload: dict[str, Any],
        event_type: NormalizedEventType,
        severity: Severity,
    ) -> NormalizedEvent:
        mac = self._require_mac(payload.get("mac"))
        timestamp = payload.get("timestamp") or payload.get("detect_date")
        return NormalizedEvent(
            raw_event_id=event.id,
            source_system=self.source_system,
            event_type=event_type,
            severity=severity,
            primary_entity=NormalizedEntity(entity_type=EntityType.DEVICE, mac_address=mac),
            occurred_at=self._parse_timestamp(timestamp) if timestamp else event.received_at,
            extra_attributes={
                key: payload[key]
                for key in ("vlan", "role", "status", "category", "switch_ip")
                if key in payload
            },
        )

    @staticmethod
    def _is_isolation_role(category: str) -> bool:
        lowered = category.casefold()
        return "isolat" in lowered or "quarant" in lowered

    @staticmethod
    def _require_mac(value: object) -> str:
        if not isinstance(value, str) or _MAC.fullmatch(value) is None:
            raise ValueError("PacketFence event requires a valid colon-separated MAC address")
        return value.lower()

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
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("Invalid PacketFence timestamp") from exc
        if parsed.tzinfo is None:
            raise ValueError("PacketFence timestamp must include a timezone")
        return parsed.astimezone(UTC)
