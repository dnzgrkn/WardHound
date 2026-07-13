"""Independent event-level policy violation engine."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Protocol

from app.schemas.events import (
    EntityType,
    NormalizedEntity,
    NormalizedEvent,
    NormalizedEventType,
    Severity,
    SourceSystem,
)
from app.schemas.incidents import PolicyViolation


@dataclass(frozen=True)
class PolicyConfig:
    """Operator-owned identity sets required to evaluate environment-specific policies."""

    tier_zero_assets: frozenset[str] = field(default_factory=frozenset)
    paw_devices: frozenset[str] = field(default_factory=frozenset)
    isolated_devices: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        object.__setattr__(self, "tier_zero_assets", _normalized_set(self.tier_zero_assets))
        object.__setattr__(self, "paw_devices", _normalized_set(self.paw_devices))
        object.__setattr__(self, "isolated_devices", _normalized_set(self.isolated_devices))


class PolicyRule(Protocol):
    """Extension point for a concrete event-level policy rule."""

    def evaluate(
        self, events: Sequence[NormalizedEvent], config: PolicyConfig
    ) -> list[PolicyViolation]:
        """Return violations supported by the supplied normalized events."""
        ...


class TierZeroFromNonPawRule:
    """Flag privileged sessions to Tier 0 assets from an unregistered access device."""

    def evaluate(
        self, events: Sequence[NormalizedEvent], config: PolicyConfig
    ) -> list[PolicyViolation]:
        violations: list[PolicyViolation] = []
        for event in events:
            if event.event_type is not NormalizedEventType.SESSION_STARTED:
                continue
            targets = _device_identifiers(event.related_entities)
            if not targets.intersection(config.tier_zero_assets):
                continue
            source = event.extra_attributes.get("source_device") or event.extra_attributes.get(
                "remote_addr"
            )
            if not isinstance(source, str) or not source:
                continue
            if _normalize_identifier(source) in config.paw_devices:
                continue
            violations.append(
                PolicyViolation(
                    rule_id="tier_zero_from_non_paw",
                    title="Tier 0 asset accessed from a non-PAW device",
                    description=(
                        "A privileged session targeted a configured Tier 0 asset from a device "
                        "that is not in the configured PAW allowlist."
                    ),
                    event_ids=[event.id],
                    entities=[event.primary_entity, *event.related_entities],
                    severity=Severity.HIGH,
                )
            )
        return violations


class QuarantineBypassRule:
    """Flag successful PacketFence access by a configured isolated device."""

    def evaluate(
        self, events: Sequence[NormalizedEvent], config: PolicyConfig
    ) -> list[PolicyViolation]:
        access_types = {
            NormalizedEventType.AUTH_SUCCEEDED,
            NormalizedEventType.VLAN_ASSIGNED,
        }
        violations: list[PolicyViolation] = []
        for event in events:
            if (
                event.source_system is not SourceSystem.PACKETFENCE
                or event.event_type not in access_types
            ):
                continue
            identifiers = _device_identifiers((event.primary_entity,))
            if not identifiers.intersection(config.isolated_devices):
                continue
            violations.append(
                PolicyViolation(
                    rule_id="quarantine_bypass_attempt",
                    title="VLAN quarantine bypass attempt",
                    description=(
                        "A device configured as isolated produced a successful network-access "
                        "or VLAN-assignment event."
                    ),
                    event_ids=[event.id],
                    entities=[event.primary_entity],
                    severity=Severity.HIGH,
                )
            )
        return violations


class PolicyEngine:
    """Evaluate a registry of policy rules against an in-memory event collection."""

    def __init__(
        self,
        config: PolicyConfig,
        rules: Iterable[PolicyRule] | None = None,
    ) -> None:
        self.config = config
        self.rules = (
            tuple(rules)
            if rules is not None
            else (TierZeroFromNonPawRule(), QuarantineBypassRule())
        )

    def evaluate(self, events: Iterable[NormalizedEvent]) -> list[PolicyViolation]:
        """Return all independently detected policy violations."""
        event_list = tuple(events)
        return [
            violation for rule in self.rules for violation in rule.evaluate(event_list, self.config)
        ]


def _device_identifiers(entities: Iterable[NormalizedEntity]) -> set[str]:
    identifiers: set[str] = set()
    for entity in entities:
        if entity.entity_type is not EntityType.DEVICE:
            continue
        for value in (entity.mac_address, entity.hostname, entity.ip_address):
            if value:
                identifiers.add(_normalize_identifier(value))
    return identifiers


def _normalized_set(values: frozenset[str]) -> frozenset[str]:
    return frozenset(_normalize_identifier(value) for value in values)


def _normalize_identifier(value: str) -> str:
    return value.strip().casefold()
