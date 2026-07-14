"""Time-windowed rule registry and correlation engine."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import timedelta
from typing import Protocol
from uuid import NAMESPACE_URL, UUID, uuid5

from app.schemas.events import (
    EntityType,
    NormalizedEntity,
    NormalizedEvent,
    NormalizedEventType,
    Severity,
    SourceSystem,
)
from app.schemas.incidents import Incident

EntityKey = tuple[str, str]

_SEVERITY_RANK = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


@dataclass(frozen=True)
class CorrelationMatch:
    """Internal evidence bundle returned by a correlation rule."""

    rule_id: str
    title: str
    summary: str
    events: tuple[NormalizedEvent, ...]
    entities: tuple[NormalizedEntity, ...]


class CorrelationRule(Protocol):
    """Small extension point implemented by concrete correlation rules."""

    def find_matches(self, events: Sequence[NormalizedEvent]) -> list[CorrelationMatch]:
        """Return every unique evidence set satisfying this rule."""
        ...


@dataclass(frozen=True)
class EventRequirement:
    """One source/type member required by a concrete correlation rule."""

    source_system: SourceSystem
    event_type: NormalizedEventType


@dataclass(frozen=True)
class CrossSystemCompromiseRule:
    """Correlate AD failure, NAC isolation, and a new privileged session."""

    window: timedelta = timedelta(minutes=15)
    rule_id: str = "cross_system_auth_quarantine_session"
    title: str = "Cross-system access after authentication failure and isolation"
    summary: str = (
        "The same resolved entity had an AD authentication failure, PacketFence isolation, "
        "and a new JumpServer session within the configured window."
    )

    def find_matches(self, events: Sequence[NormalizedEvent]) -> list[CorrelationMatch]:
        if self.window <= timedelta(0):
            raise ValueError("Correlation window must be positive")
        requirements = (
            EventRequirement(SourceSystem.ACTIVE_DIRECTORY, NormalizedEventType.AUTH_FAILED),
            EventRequirement(SourceSystem.PACKETFENCE, NormalizedEventType.DEVICE_QUARANTINED),
            EventRequirement(SourceSystem.JUMPSERVER, NormalizedEventType.SESSION_STARTED),
        )
        buckets = tuple(
            [
                event
                for event in events
                if event.source_system is requirement.source_system
                and event.event_type is requirement.event_type
            ]
            for requirement in requirements
        )
        if any(not bucket for bucket in buckets):
            return []

        matches: list[CorrelationMatch] = []
        seen_event_sets: set[tuple[UUID, ...]] = set()
        candidate_keys = set.intersection(
            *({key for event in bucket for key in _entity_keys(event)} for bucket in buckets)
        )
        for entity_key in sorted(candidate_keys):
            entity_events = sorted(
                {
                    event.id: event
                    for bucket in buckets
                    for event in bucket
                    if entity_key in _entity_keys(event)
                }.values(),
                key=lambda event: (event.occurred_at, str(event.id)),
            )
            start = 0
            while start < len(entity_events):
                cluster_end = entity_events[start].occurred_at + self.window
                stop = start
                while (
                    stop < len(entity_events)
                    and entity_events[stop].occurred_at <= cluster_end
                ):
                    stop += 1
                cluster = tuple(entity_events[start:stop])
                satisfies_requirements = all(
                    any(
                        event.source_system is requirement.source_system
                        and event.event_type is requirement.event_type
                        for event in cluster
                    )
                    for requirement in requirements
                )
                if satisfies_requirements and entity_key in _shared_entity_keys(cluster):
                    event_key = tuple(sorted((event.id for event in cluster), key=str))
                    if event_key not in seen_event_sets:
                        seen_event_sets.add(event_key)
                        matches.append(
                            CorrelationMatch(
                                rule_id=self.rule_id,
                                title=self.title,
                                summary=self.summary,
                                events=cluster,
                                entities=tuple(_unique_entities(cluster)),
                            )
                        )
                    start = stop
                else:
                    start += 1
        return matches


class CorrelationEngine:
    """Run a registry of concrete rules without coupling the core loop to rule details."""

    def __init__(self, rules: Iterable[CorrelationRule] | None = None) -> None:
        self.rules = tuple(rules) if rules is not None else (CrossSystemCompromiseRule(),)

    def correlate(self, events: Iterable[NormalizedEvent]) -> list[Incident]:
        """Return deterministic incident candidates for all registered rule matches."""
        event_list = tuple(events)
        incidents: list[Incident] = []
        for rule in self.rules:
            for match in rule.find_matches(event_list):
                event_ids = [event.id for event in match.events]
                stable_name = f"{match.rule_id}:{','.join(sorted(map(str, event_ids)))}"
                incidents.append(
                    Incident(
                        id=uuid5(NAMESPACE_URL, stable_name),
                        title=match.title,
                        summary=match.summary,
                        event_ids=event_ids,
                        entities=list(match.entities),
                        severity=max(
                            (event.severity for event in match.events),
                            key=_SEVERITY_RANK.__getitem__,
                        ),
                        risk_score=0,
                        created_at=max(event.occurred_at for event in match.events),
                        correlation_rule_id=match.rule_id,
                    )
                )
        return incidents


def _entity_keys(event: NormalizedEvent) -> set[EntityKey]:
    keys: set[EntityKey] = set()
    for entity in (event.primary_entity, *event.related_entities):
        if entity.username:
            keys.add((EntityType.USER.value, entity.username.casefold()))
        if entity.mac_address:
            keys.add((EntityType.DEVICE.value, entity.mac_address.casefold().replace("-", ":")))
    return keys


def _shared_entity_keys(events: Sequence[NormalizedEvent]) -> set[EntityKey]:
    event_keys = [_entity_keys(event) for event in events]
    username_keys = [
        {key for key in keys if key[0] == EntityType.USER.value} for keys in event_keys
    ]
    if all(username_keys):
        return set.intersection(*username_keys)
    mac_keys = [{key for key in keys if key[0] == EntityType.DEVICE.value} for keys in event_keys]
    return set.intersection(*mac_keys)


def _unique_entities(events: Sequence[NormalizedEvent]) -> list[NormalizedEntity]:
    entities: list[NormalizedEntity] = []
    seen: set[tuple[str | None, ...]] = set()
    for event in events:
        for entity in (event.primary_entity, *event.related_entities):
            identity = (
                entity.entity_type.value,
                entity.username,
                entity.domain,
                entity.mac_address,
                entity.hostname,
                entity.ip_address,
            )
            if identity not in seen:
                seen.add(identity)
                entities.append(entity)
    return entities
