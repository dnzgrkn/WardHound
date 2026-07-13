"""Active Directory Windows Security event collector."""

from __future__ import annotations

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


class ActiveDirectoryCollector(BaseCollector):
    """Normalize the three single-event AD signals in the Stage 2 scope."""

    @property
    def source_system(self) -> SourceSystem:
        return SourceSystem.ACTIVE_DIRECTORY

    def parse_raw(self, data: bytes | str | dict[str, Any]) -> RawEvent:
        # Upstream transports must render each event with .ToXml(); named fields such as
        # TargetUserName do not exist in Format-List or raw positional .Properties output.
        if not isinstance(data, dict):
            raise ValueError("Active Directory input must be an event object")
        try:
            int(data["EventID"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("Active Directory event requires a numeric EventID") from exc
        source_host = data.get("Computer") or data.get("source_host")
        if not isinstance(source_host, str) or not source_host:
            raise ValueError("Active Directory event requires Computer or source_host")
        return RawEvent(
            source_system=self.source_system,
            source_host=source_host,
            raw_payload=dict(data),
        )

    def normalize(self, event: RawEvent) -> NormalizedEvent:
        payload = self._payload(event)
        event_id = int(payload["EventID"])
        mappings = {
            4625: (NormalizedEventType.AUTH_FAILED, Severity.MEDIUM),
            4740: (NormalizedEventType.ACCOUNT_LOCKED_OUT, Severity.HIGH),
            4728: (NormalizedEventType.GROUP_MEMBERSHIP_CHANGED, Severity.HIGH),
        }
        if event_id not in mappings:
            raise ValueError(f"Unsupported Active Directory EventID: {event_id}")

        username = payload.get("TargetUserName") or payload.get("MemberName")
        domain = payload.get("TargetDomainName")
        if not isinstance(username, str) or not username:
            raise ValueError("Active Directory event requires a target username")
        event_type, severity = mappings[event_id]
        return NormalizedEvent(
            raw_event_id=event.id,
            source_system=self.source_system,
            event_type=event_type,
            severity=severity,
            primary_entity=NormalizedEntity(
                entity_type=EntityType.USER,
                username=username,
                domain=domain if isinstance(domain, str) and domain else None,
            ),
            occurred_at=self._parse_timestamp(payload.get("TimeCreated")),
            extra_attributes={
                key: payload[key]
                for key in ("EventID", "IpAddress", "CallerComputerName", "GroupName")
                if key in payload
            },
        )

    @staticmethod
    def _payload(event: RawEvent) -> dict[str, Any]:
        if event.source_system is not SourceSystem.ACTIVE_DIRECTORY or not isinstance(
            event.raw_payload, dict
        ):
            raise ValueError("RawEvent is not a structured Active Directory event")
        return event.raw_payload

    @staticmethod
    def _parse_timestamp(value: object) -> datetime:
        if not isinstance(value, str):
            raise ValueError("Active Directory event requires TimeCreated")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("Invalid Active Directory TimeCreated") from exc
        if parsed.tzinfo is None:
            raise ValueError("Active Directory TimeCreated must include a timezone")
        return parsed.astimezone(UTC)
