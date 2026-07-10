"""JumpServer polling collector."""

from __future__ import annotations

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


class JumpServerCollector(BaseCollector):
    """Normalize flat JumpServer audit API records."""

    def __init__(self, api_url: str = "/api/v1/audits/events/") -> None:
        self.api_url = api_url

    @property
    def source_system(self) -> SourceSystem:
        return SourceSystem.JUMPSERVER

    def parse_raw(self, data: bytes | str | dict[str, Any]) -> RawEvent:
        if not isinstance(data, dict):
            raise ValueError("JumpServer input must be a JSON-decoded object")
        required = ("event_type", "username", "timestamp")
        if any(not isinstance(data.get(field), str) or not data[field] for field in required):
            raise ValueError("JumpServer event requires event_type, username, and timestamp")
        source_host = data.get("source_host", "jumpserver.local")
        if not isinstance(source_host, str) or not source_host:
            raise ValueError("JumpServer source_host must be a non-empty string")
        return RawEvent(
            source_system=self.source_system,
            source_host=source_host,
            raw_payload=dict(data),
        )

    def normalize(self, event: RawEvent) -> NormalizedEvent:
        payload = self._payload(event)
        name = str(payload["event_type"]).lower().replace("-", "_")
        mappings = {
            "session_started": (NormalizedEventType.SESSION_STARTED, Severity.LOW),
            "session_ended": (NormalizedEventType.SESSION_ENDED, Severity.LOW),
            "privileged_command_executed": (
                NormalizedEventType.PRIVILEGED_COMMAND_EXECUTED,
                Severity.HIGH,
            ),
            "session_anomaly_detected": (
                NormalizedEventType.SESSION_ANOMALY_DETECTED,
                Severity.HIGH,
            ),
            "auth_failed": (NormalizedEventType.AUTH_FAILED, Severity.MEDIUM),
        }
        if name not in mappings:
            raise ValueError(f"Unrecognized JumpServer event: {name}")
        username = payload.get("username")
        if not isinstance(username, str) or not username:
            raise ValueError("JumpServer event requires a username")

        related: list[NormalizedEntity] = []
        target_host = payload.get("target_host")
        target_ip = payload.get("target_ip")
        if isinstance(target_host, str) and target_host:
            related.append(NormalizedEntity(entity_type=EntityType.DEVICE, hostname=target_host))
        elif isinstance(target_ip, str) and target_ip:
            related.append(
                NormalizedEntity(entity_type=EntityType.IP_ADDRESS, ip_address=target_ip)
            )

        event_type, severity = mappings[name]
        return NormalizedEvent(
            raw_event_id=event.id,
            source_system=self.source_system,
            event_type=event_type,
            severity=severity,
            primary_entity=NormalizedEntity(entity_type=EntityType.USER, username=username),
            related_entities=related,
            occurred_at=self._parse_timestamp(payload.get("timestamp")),
            extra_attributes={
                key: payload[key] for key in ("session_id", "command", "reason") if key in payload
            },
        )

    async def poll(self, client: httpx.AsyncClient, since: datetime) -> list[NormalizedEvent]:
        """Fetch audit records newer than ``since`` and normalize each one."""
        response = await client.get(self.api_url, params={"since": since.isoformat()})
        response.raise_for_status()
        body = response.json()
        if not isinstance(body, list) or not all(isinstance(item, dict) for item in body):
            raise ValueError("JumpServer API response must be a list of objects")
        return [self.process(item) for item in body]

    @staticmethod
    def _payload(event: RawEvent) -> dict[str, Any]:
        if event.source_system is not SourceSystem.JUMPSERVER or not isinstance(
            event.raw_payload, dict
        ):
            raise ValueError("RawEvent is not a structured JumpServer event")
        return event.raw_payload

    @staticmethod
    def _parse_timestamp(value: object) -> datetime:
        if not isinstance(value, str):
            raise ValueError("JumpServer event requires a timestamp")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("Invalid JumpServer timestamp") from exc
        if parsed.tzinfo is None:
            raise ValueError("JumpServer timestamp must include a timezone")
        return parsed.astimezone(UTC)
