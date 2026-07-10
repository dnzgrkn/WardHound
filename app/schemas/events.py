"""
Core event contracts for WardHound.

Every collector, the correlation engine, and the AI analysis layer imports
from this module. These schemas are the canonical wire format between all
pipeline stages. Change carefully — breaking changes here ripple everywhere.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, model_validator

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class SourceSystem(StrEnum):
    """The four supported enterprise event sources in scope for v1."""

    PACKETFENCE = "packetfence"
    JUMPSERVER = "jumpserver"
    ACTIVE_DIRECTORY = "active_directory"
    FIREWALL = "firewall"


class NormalizedEventType(StrEnum):
    """
    Semantic event vocabulary shared across all source systems.

    The goal is cross-source correlation: an AUTH_FAILED from PacketFence and
    an AUTH_FAILED from Active Directory are the same semantic event type,
    distinguished only by source_system. This enables the correlation engine
    to detect patterns like "N auth failures across NAC + AD in T seconds"
    without source-specific logic.

    Naming convention: NOUN_VERB_past_tense (what happened, not what triggered it).
    """

    # --- Authentication events (emitted by PacketFence, AD, JumpServer) ---
    AUTH_FAILED = "auth_failed"
    AUTH_SUCCEEDED = "auth_succeeded"
    ACCOUNT_LOCKED_OUT = "account_locked_out"

    # --- NAC / network admission (PacketFence) ---
    DEVICE_UNKNOWN = "device_unknown"
    DEVICE_REGISTERED = "device_registered"
    DEVICE_QUARANTINED = "device_quarantined"
    VLAN_ASSIGNED = "vlan_assigned"

    # --- PAM / privileged access (JumpServer) ---
    SESSION_STARTED = "session_started"
    SESSION_ENDED = "session_ended"
    PRIVILEGED_COMMAND_EXECUTED = "privileged_command_executed"
    SESSION_ANOMALY_DETECTED = "session_anomaly_detected"

    # --- Identity / directory (Active Directory) ---
    PASSWORD_SPRAY_DETECTED = "password_spray_detected"
    GROUP_MEMBERSHIP_CHANGED = "group_membership_changed"
    TIER_VIOLATION_DETECTED = "tier_violation_detected"

    # --- Network / perimeter (Firewall) ---
    TRAFFIC_BLOCKED = "traffic_blocked"
    LATERAL_MOVEMENT_ATTEMPT = "lateral_movement_attempt"
    PORT_SCAN_DETECTED = "port_scan_detected"
    UNEXPECTED_EAST_WEST_TRAFFIC = "unexpected_east_west_traffic"


class Severity(StrEnum):
    """Normalized severity levels. Mapped from source-system-specific levels by each collector."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EntityType(StrEnum):
    """
    The primary kind of subject in an event.

    USER: a human identity (Active Directory account, JumpServer user).
    DEVICE: a network endpoint identified by MAC or hostname (PacketFence).
    IP_ADDRESS: a network address without a resolved identity (firewall events).
    """

    USER = "user"
    DEVICE = "device"
    IP_ADDRESS = "ip_address"


# ---------------------------------------------------------------------------
# Entity model
# ---------------------------------------------------------------------------


class NormalizedEntity(BaseModel):
    """
    A normalized representation of the primary actor or subject of an event.

    Design note: we use a single model with optional identity fields rather
    than a discriminated union. This reflects the reality that real events
    are often partially identified — e.g., a PacketFence auth failure knows
    the MAC address but not the username until 802.1X EAP exchange completes,
    while an AD auth failure knows the username but not the device.

    At least one identifying field must be non-null (enforced by validator).
    """

    entity_type: EntityType

    # User identity fields (AD, JumpServer)
    username: str | None = None
    domain: str | None = None

    # Device identity fields (PacketFence)
    mac_address: str | None = None
    hostname: str | None = None

    # Network identity fields (firewall, fallback for others)
    ip_address: str | None = None

    @model_validator(mode="after")
    def require_at_least_one_identifier(self) -> NormalizedEntity:
        identifiers = (
            self.username,
            self.mac_address,
            self.hostname,
            self.ip_address,
        )
        if not any(identifiers):
            raise ValueError(
                "NormalizedEntity must have at least one identifying field set "
                "(username, mac_address, hostname, or ip_address)"
            )
        return self

    @property
    def display_name(self) -> str:
        """Human-readable label for this entity, used in AI prompts and UI."""
        if self.username:
            return f"{self.domain}\\{self.username}" if self.domain else self.username
        if self.hostname:
            return self.hostname
        if self.mac_address:
            return self.mac_address
        return self.ip_address or "unknown"


# ---------------------------------------------------------------------------
# Raw event — what arrives directly from a source system
# ---------------------------------------------------------------------------


class RawEvent(BaseModel):
    """
    An event exactly as received from a source system, before any normalization.

    Collectors produce RawEvents. The payload is intentionally untyped (dict or
    string) because each source system has its own schema. Normalization happens
    in a subsequent step via the collector's normalize() method.

    Immutable by design: model_config forbids mutation after construction.
    """

    model_config = {"frozen": True}

    id: UUID = Field(default_factory=uuid4)
    source_system: SourceSystem
    source_host: str = Field(
        description="FQDN or IP of the host that sent this event (e.g. the syslog sender).",
        min_length=1,
    )
    raw_payload: dict[str, Any] | str = Field(
        description="Raw event data as received. Dict for structured (JSON/API) sources, "
        "str for syslog/text sources.",
    )
    received_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp when WardHound received this event.",
    )


# ---------------------------------------------------------------------------
# Normalized event — the common contract consumed by all downstream engines
# ---------------------------------------------------------------------------


class NormalizedEvent(BaseModel):
    """
    A source-agnostic event representation consumed by the correlation, risk,
    policy, and AI analysis engines.

    Design decisions:
    - primary_entity is the main actor (user performing action, device triggering NAC).
    - related_entities captures secondary subjects (target host of a JumpServer session,
      destination IP of a firewall block, etc.). Kept as a list to support multi-party
      events without forcing a fixed secondary/tertiary structure.
    - raw_event_id links back to the original RawEvent for auditability and replay.
    - extra_attributes is an escape hatch for source-specific fields that the correlation
      or AI engine might use (e.g., AD event ID, PacketFence role, firewall rule name)
      without polluting the canonical schema with rarely-used fields.

    Immutable by design for the same reason as RawEvent.
    """

    model_config = {"frozen": True}

    id: UUID = Field(default_factory=uuid4)
    raw_event_id: UUID = Field(description="ID of the originating RawEvent.")

    source_system: SourceSystem
    event_type: NormalizedEventType
    severity: Severity

    primary_entity: NormalizedEntity = Field(
        description="The main actor or subject of the event."
    )
    related_entities: list[NormalizedEntity] = Field(
        default_factory=list,
        description="Secondary entities involved (target host, destination IP, etc.).",
    )

    occurred_at: datetime = Field(
        description="UTC timestamp of the event as reported by the source system. "
        "Prefer source-system time over ingestion time for accurate correlation.",
    )
    normalized_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp when normalization completed.",
    )

    extra_attributes: dict[str, Any] = Field(
        default_factory=dict,
        description="Source-specific fields preserved for AI context and deep-dive queries. "
        "Do not use these in correlation rules — promote to top-level fields instead.",
    )
