"""JumpServer REST API polling collector."""

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

_DISPLAY_USERNAME = re.compile(r"^.*\(([^()]+)\)$")
_LOGIN_DATETIME_FORMAT = "%Y/%m/%d %H:%M:%S %z"


class JumpServerCollector(BaseCollector):
    """Normalize login logs, sessions, and commands from JumpServer REST APIs."""

    def __init__(
        self,
        login_url: str = "/api/v1/audits/login-logs/",
        sessions_url: str = "/api/v1/terminal/sessions/",
        commands_url: str = "/api/v1/terminal/commands/",
    ) -> None:
        self.login_url = login_url
        self.sessions_url = sessions_url
        self.commands_url = commands_url
        self._session_finished: dict[str, bool] = {}

    @property
    def source_system(self) -> SourceSystem:
        return SourceSystem.JUMPSERVER

    def parse_raw(self, data: bytes | str | dict[str, Any]) -> RawEvent:
        if not isinstance(data, dict):
            raise ValueError("JumpServer input must be a JSON-decoded object")
        payload = dict(data)
        kind = payload.get("kind") or self._infer_kind(payload)
        payload["kind"] = kind
        source_host = payload.get("source_host", "jumpserver.local")
        if not isinstance(source_host, str) or not source_host:
            raise ValueError("JumpServer source_host must be a non-empty string")
        self._validate_required(payload, kind)
        return RawEvent(
            source_system=self.source_system,
            source_host=source_host,
            raw_payload=payload,
        )

    def normalize(self, event: RawEvent) -> NormalizedEvent:
        payload = self._payload(event)
        kind = payload.get("kind")
        if kind == "login":
            return self._normalize_login(event, payload)
        if kind == "session":
            return self._normalize_session(event, payload)
        if kind == "command":
            return self._normalize_command(event, payload)
        raise ValueError("Unrecognized JumpServer record type")

    async def poll(self, client: httpx.AsyncClient, since: datetime) -> list[NormalizedEvent]:
        """Poll each JumpServer resource with its source-specific time encoding."""
        if since.tzinfo is None:
            raise ValueError("JumpServer poll since timestamp must include a timezone")
        login_since = since.strftime(_LOGIN_DATETIME_FORMAT)
        session_since = since.astimezone(UTC).isoformat().replace("+00:00", "Z")
        command_since = str(int(since.timestamp()))
        login_records = await self._fetch_records(
            client, self.login_url, {"date_from": login_since}
        )
        session_records = await self._fetch_records(
            client, self.sessions_url, {"date_start_from": session_since}
        )
        command_records = await self._fetch_records(
            client, self.commands_url, {"timestamp_from": command_since}
        )

        events = [self.process({**record, "kind": "login"}) for record in login_records]
        for record in session_records:
            session_id = record.get("id")
            finished = record.get("is_finished")
            if not isinstance(session_id, str) or not session_id or not isinstance(finished, bool):
                raise ValueError("JumpServer session requires id and boolean is_finished")
            previous = self._session_finished.get(session_id)
            self._session_finished[session_id] = finished
            if (previous is None and not finished) or (previous is False and finished):
                events.append(self.process({**record, "kind": "session"}))
        events.extend(self.process({**record, "kind": "command"}) for record in command_records)
        return events

    async def _fetch_records(
        self, client: httpx.AsyncClient, url: str, params: dict[str, str]
    ) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        next_url: str | None = url
        next_params: dict[str, str] | None = params
        while next_url is not None:
            response = await client.get(next_url, params=next_params)
            response.raise_for_status()
            body = response.json()
            if not isinstance(body, dict) or not isinstance(body.get("results"), list):
                raise ValueError("JumpServer API response must be a paginated results envelope")
            page = body["results"]
            if not all(isinstance(item, dict) for item in page):
                raise ValueError("JumpServer API results must contain objects")
            records.extend(page)
            candidate = body.get("next")
            if candidate is not None and not isinstance(candidate, str):
                raise ValueError("JumpServer API next link must be a string or null")
            next_url = candidate
            next_params = None
        return records

    def _normalize_login(self, event: RawEvent, payload: dict[str, Any]) -> NormalizedEvent:
        status = self._choice_value(payload.get("status"), "status")
        if not isinstance(status, bool):
            raise ValueError("JumpServer login status.value must be a boolean")
        raw_username = payload.get("username")
        if not isinstance(raw_username, str) or not raw_username:
            raise ValueError("JumpServer login requires username")
        match = _DISPLAY_USERNAME.fullmatch(raw_username)
        username = match.group(1) if match else raw_username
        return NormalizedEvent(
            raw_event_id=event.id,
            source_system=self.source_system,
            event_type=(
                NormalizedEventType.AUTH_SUCCEEDED if status else NormalizedEventType.AUTH_FAILED
            ),
            severity=Severity.LOW if status else Severity.MEDIUM,
            primary_entity=NormalizedEntity(entity_type=EntityType.USER, username=username),
            related_entities=self._remote_address_entity(payload.get("ip")),
            occurred_at=self._parse_login_datetime(payload.get("datetime")),
            extra_attributes={
                key: payload[key]
                for key in ("id", "reason", "reason_display", "backend", "backend_display")
                if key in payload
            }
            | {
                "login_type": self._choice_value(payload.get("type"), "type"),
                "mfa": self._choice_value(payload.get("mfa"), "mfa"),
            },
        )

    def _normalize_session(self, event: RawEvent, payload: dict[str, Any]) -> NormalizedEvent:
        finished = payload.get("is_finished")
        if not isinstance(finished, bool):
            raise ValueError("JumpServer session is_finished must be a boolean")
        username = payload.get("user")
        if not isinstance(username, str) or not username:
            raise ValueError("JumpServer session requires user")
        timestamp = payload.get("date_end") if finished else payload.get("date_start")
        if finished and not timestamp:
            raise ValueError("Finished JumpServer session requires date_end")
        return NormalizedEvent(
            raw_event_id=event.id,
            source_system=self.source_system,
            event_type=(
                NormalizedEventType.SESSION_ENDED
                if finished
                else NormalizedEventType.SESSION_STARTED
            ),
            severity=Severity.LOW,
            primary_entity=NormalizedEntity(entity_type=EntityType.USER, username=username),
            related_entities=self._asset_entity(payload.get("asset")),
            occurred_at=self._parse_iso_datetime(timestamp),
            extra_attributes={
                key: payload[key]
                for key in (
                    "id",
                    "user_id",
                    "asset_id",
                    "account",
                    "account_id",
                    "login_from",
                    "is_success",
                    "command_amount",
                    "protocol",
                    "remote_addr",
                )
                if key in payload
            },
        )

    def _normalize_command(self, event: RawEvent, payload: dict[str, Any]) -> NormalizedEvent:
        username = payload.get("user")
        if not isinstance(username, str) or not username:
            raise ValueError("JumpServer command requires user")
        risk = self._choice_value(payload.get("risk_level"), "risk_level")
        if not isinstance(risk, int) or isinstance(risk, bool) or risk not in {0, 4, 5, 6, 7, 8}:
            raise ValueError("JumpServer command has an unsupported risk_level.value")
        event_type, severity = self._risk_mapping(risk)
        timestamp = payload.get("timestamp")
        if not isinstance(timestamp, int) or isinstance(timestamp, bool):
            raise ValueError("JumpServer command timestamp must be an integer Unix epoch")
        return NormalizedEvent(
            raw_event_id=event.id,
            source_system=self.source_system,
            event_type=event_type,
            severity=severity,
            primary_entity=NormalizedEntity(entity_type=EntityType.USER, username=username),
            related_entities=self._asset_entity(payload.get("asset")),
            occurred_at=datetime.fromtimestamp(timestamp, tz=UTC),
            extra_attributes={
                key: payload[key]
                for key in ("account", "input", "output", "session", "remote_addr")
                if key in payload
            }
            | {"risk_level": risk},
        )

    @staticmethod
    def _risk_mapping(risk: int) -> tuple[NormalizedEventType, Severity]:
        mappings = {
            0: (NormalizedEventType.PRIVILEGED_COMMAND_EXECUTED, Severity.LOW),
            7: (NormalizedEventType.PRIVILEGED_COMMAND_EXECUTED, Severity.MEDIUM),
            4: (NormalizedEventType.PRIVILEGED_COMMAND_EXECUTED, Severity.HIGH),
            8: (NormalizedEventType.PRIVILEGED_COMMAND_EXECUTED, Severity.HIGH),
            5: (NormalizedEventType.SESSION_ANOMALY_DETECTED, Severity.HIGH),
            6: (NormalizedEventType.SESSION_ANOMALY_DETECTED, Severity.CRITICAL),
        }
        return mappings[risk]

    @staticmethod
    def _infer_kind(payload: dict[str, Any]) -> str:
        if "datetime" in payload and "status" in payload and "username" in payload:
            return "login"
        if "date_start" in payload and "is_finished" in payload:
            return "session"
        if "timestamp" in payload and "risk_level" in payload and "input" in payload:
            return "command"
        raise ValueError("Unrecognized JumpServer record shape")

    @staticmethod
    def _validate_required(payload: dict[str, Any], kind: object) -> None:
        required = {
            "login": ("username", "status", "datetime", "type", "mfa"),
            "session": ("id", "user", "asset", "date_start", "is_finished"),
            "command": ("user", "asset", "input", "timestamp", "risk_level"),
        }
        if kind not in required:
            raise ValueError("Unrecognized JumpServer record type")
        missing = [field for field in required[str(kind)] if field not in payload]
        if missing:
            raise ValueError(f"JumpServer {kind} record missing fields: {', '.join(missing)}")

    @staticmethod
    def _choice_value(value: object, field: str) -> object:
        if not isinstance(value, dict) or "value" not in value:
            raise ValueError(f"JumpServer {field} must be a labeled-choice object")
        return value["value"]

    @staticmethod
    def _asset_entity(value: object) -> list[NormalizedEntity]:
        if not isinstance(value, str) or not value:
            raise ValueError("JumpServer record requires asset")
        return [NormalizedEntity(entity_type=EntityType.DEVICE, hostname=value)]

    @staticmethod
    def _remote_address_entity(value: object) -> list[NormalizedEntity]:
        if isinstance(value, str) and value:
            return [NormalizedEntity(entity_type=EntityType.IP_ADDRESS, ip_address=value)]
        return []

    @staticmethod
    def _payload(event: RawEvent) -> dict[str, Any]:
        if event.source_system is not SourceSystem.JUMPSERVER or not isinstance(
            event.raw_payload, dict
        ):
            raise ValueError("RawEvent is not a structured JumpServer event")
        return event.raw_payload

    @staticmethod
    def _parse_login_datetime(value: object) -> datetime:
        if not isinstance(value, str):
            raise ValueError("JumpServer login requires datetime")
        try:
            return datetime.strptime(value, _LOGIN_DATETIME_FORMAT).astimezone(UTC)
        except ValueError as exc:
            raise ValueError("Invalid JumpServer login datetime") from exc

    @staticmethod
    def _parse_iso_datetime(value: object) -> datetime:
        if not isinstance(value, str):
            raise ValueError("JumpServer session requires an ISO 8601 timestamp")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("Invalid JumpServer session timestamp") from exc
        if parsed.tzinfo is None:
            raise ValueError("JumpServer session timestamp must include a timezone")
        return parsed.astimezone(UTC)
