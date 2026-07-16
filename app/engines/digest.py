"""Deterministic daily digest aggregation with an optional typed AI narrative."""

from __future__ import annotations

import json
import os
from collections import Counter
from collections.abc import Callable, Iterable, Sequence
from datetime import datetime
from typing import Literal, Protocol, TypedDict, cast
from uuid import UUID

import anthropic
import instructor

from app.engines.analysis import AnalysisConfigurationError
from app.engines.response import ApprovalStore
from app.schemas.digest import AggregateStat, DailyDigest, DigestNarrative
from app.schemas.events import EntityType, NormalizedEntity, NormalizedEvent, NormalizedEventType
from app.schemas.incidents import Incident
from app.schemas.response import ActionAuditRecord, ApprovalStatus, ExecutionStatus
from app.stores.incidents import EventStore, IncidentStore

DEFAULT_DIGEST_MODEL = "claude-sonnet-5"
DEFAULT_MAX_TOKENS = 1536
DEFAULT_MAX_RETRIES = 2
DEFAULT_RANKING_LIMIT = 10

SYSTEM_PROMPT = """You are WardHound's enterprise security digest analyst.
Return only the requested DigestNarrative structure. Summarize the supplied deterministic facts
for security operators. Do not invent events, identities, causes, commands, scripts, or response
actions. Keep the executive summary short, make highlights evidence-based, and phrase follow-up
items as operator review recommendations rather than autonomous infrastructure changes.
"""


class DigestMessage(TypedDict):
    """Minimal message shape shared by the adapter and test doubles."""

    role: Literal["user", "assistant"]
    content: str


class DigestNarrativeClient(Protocol):
    """Provider-neutral async client for validated digest narratives."""

    async def create_narrative(
        self,
        *,
        model: str,
        max_tokens: int,
        system: str,
        messages: list[DigestMessage],
        max_retries: int,
    ) -> DigestNarrative:
        """Return one validated narrative."""
        ...


class _InstructorMessages(Protocol):
    async def create(
        self,
        *,
        response_model: type[DigestNarrative],
        model: str,
        max_tokens: int,
        system: str,
        messages: list[DigestMessage],
        max_retries: int,
    ) -> DigestNarrative: ...


class InstructorDigestNarrativeClient:
    """Small adapter around Instructor's async Anthropic messages client."""

    def __init__(self, messages_client: _InstructorMessages) -> None:
        self._messages_client = messages_client

    async def create_narrative(
        self,
        *,
        model: str,
        max_tokens: int,
        system: str,
        messages: list[DigestMessage],
        max_retries: int,
    ) -> DigestNarrative:
        return await self._messages_client.create(
            response_model=DigestNarrative,
            model=model,
            max_tokens=max_tokens,
            system=system,
            messages=messages,
            max_retries=max_retries,
        )


class DigestNarrativeGenerationError(RuntimeError):
    """Raised when provider generation or typed validation fails."""


class AIDigestNarrativeEngine:
    """Turn already-computed digest facts into a typed executive narrative."""

    def __init__(
        self,
        client: DigestNarrativeClient,
        *,
        model: str = DEFAULT_DIGEST_MODEL,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        max_retries: int = DEFAULT_MAX_RETRIES,
    ) -> None:
        if not model:
            raise ValueError("Digest model must be non-empty")
        if max_tokens <= 0:
            raise ValueError("Digest max_tokens must be positive")
        if max_retries < 0:
            raise ValueError("Digest max_retries cannot be negative")
        self.client = client
        self.model = model
        self.max_tokens = max_tokens
        self.max_retries = max_retries

    async def narrate(
        self, aggregate_stats: Sequence[AggregateStat], incidents: Sequence[Incident]
    ) -> DigestNarrative:
        messages = [
            DigestMessage(
                role="user",
                content=_build_narrative_prompt(aggregate_stats, incidents),
            )
        ]
        try:
            return await self.client.create_narrative(
                model=self.model,
                max_tokens=self.max_tokens,
                system=SYSTEM_PROMPT,
                messages=messages,
                max_retries=self.max_retries,
            )
        except Exception as exc:
            raise DigestNarrativeGenerationError(
                "AI digest narrative generation or structured validation failed"
            ) from exc


class DigestNarrativeEngine(Protocol):
    """Async narrative behavior required by the digest builder."""

    async def narrate(
        self, aggregate_stats: Sequence[AggregateStat], incidents: Sequence[Incident]
    ) -> DigestNarrative:
        """Return one structured narrative for deterministic digest facts."""
        ...


DigestNarrativeEngineFactory = Callable[[], DigestNarrativeEngine]


def create_digest_narrative_engine_from_env() -> AIDigestNarrativeEngine:
    """Construct the Anthropic/Instructor adapter only when a key is configured."""
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise AnalysisConfigurationError("ANTHROPIC_API_KEY is required for AI narratives")
    model = os.getenv("WARDHOUND_DIGEST_MODEL", DEFAULT_DIGEST_MODEL)
    if not model:
        raise AnalysisConfigurationError("WARDHOUND_DIGEST_MODEL must be non-empty")
    anthropic_client = anthropic.AsyncAnthropic(api_key=api_key)
    structured_client = instructor.from_anthropic(anthropic_client)
    adapter = InstructorDigestNarrativeClient(
        cast(_InstructorMessages, structured_client.messages)
    )
    return AIDigestNarrativeEngine(client=adapter, model=model)


class DigestBuilder:
    """Build one reproducible digest over a half-open time window."""

    def __init__(
        self,
        events: EventStore,
        incidents: IncidentStore,
        approvals: ApprovalStore,
        narrative_engine_factory: DigestNarrativeEngineFactory | None = None,
        *,
        ranking_limit: int = DEFAULT_RANKING_LIMIT,
    ) -> None:
        if ranking_limit <= 0:
            raise ValueError("Digest ranking_limit must be positive")
        self.events = events
        self.incidents = incidents
        self.approvals = approvals
        self.narrative_engine_factory = narrative_engine_factory
        self.ranking_limit = ranking_limit

    async def build(self, period_start: datetime, period_end: datetime) -> DailyDigest:
        """Aggregate activity in ``[period_start, period_end)`` and optionally narrate it."""
        if period_start.tzinfo is None or period_end.tzinfo is None:
            raise ValueError("Digest period timestamps must be timezone-aware")
        if period_start >= period_end:
            raise ValueError("Digest period_start must be before period_end")

        all_events = await self.events.get_all()
        all_incidents = await self.incidents.list_all()
        window_events = [
            event
            for event in all_events
            if _in_window(event.occurred_at, period_start, period_end)
        ]
        window_incidents = sorted(
            (
                incident
                for incident in all_incidents
                if _in_window(incident.created_at, period_start, period_end)
            ),
            key=lambda incident: (incident.created_at, str(incident.id)),
        )
        actions = await _latest_actions(self.approvals, all_incidents)
        window_actions = [
            action
            for action in actions
            if _in_window(_action_timestamp(action), period_start, period_end)
        ]
        aggregate_stats = _aggregate(
            window_events,
            window_incidents,
            window_actions,
            ranking_limit=self.ranking_limit,
        )
        narrative = await self._narrative_or_none(aggregate_stats, window_incidents)
        return DailyDigest(
            period_start=period_start,
            period_end=period_end,
            incidents=window_incidents,
            aggregate_stats=aggregate_stats,
            narrative=narrative,
        )

    async def _narrative_or_none(
        self,
        aggregate_stats: Sequence[AggregateStat],
        incidents: Sequence[Incident],
    ) -> DigestNarrative | None:
        if self.narrative_engine_factory is None:
            return None
        try:
            engine = self.narrative_engine_factory()
        except AnalysisConfigurationError:
            return None
        return await engine.narrate(aggregate_stats, incidents)


def _aggregate(
    events: Iterable[NormalizedEvent],
    incidents: Sequence[Incident],
    actions: Sequence[ActionAuditRecord],
    *,
    ranking_limit: int,
) -> list[AggregateStat]:
    event_list = tuple(events)
    stats: list[AggregateStat] = []
    stats.extend(
        _rank_entities(
            event_list,
            {NormalizedEventType.AUTH_FAILED},
            EntityType.USER,
            "failed_authentication_by_user",
            ranking_limit,
        )
    )
    stats.extend(
        _rank_entities(
            event_list,
            {
                NormalizedEventType.DEVICE_QUARANTINED,
                NormalizedEventType.DEVICE_UNKNOWN,
            },
            EntityType.DEVICE,
            "device_security_activity",
            ranking_limit,
        )
    )
    stats.extend(
        _rank_entities(
            event_list,
            {
                NormalizedEventType.PRIVILEGED_COMMAND_EXECUTED,
                NormalizedEventType.SESSION_ANOMALY_DETECTED,
            },
            EntityType.USER,
            "privileged_activity_by_user",
            ranking_limit,
        )
    )

    severity_counts = Counter(incident.severity.value for incident in incidents)
    for severity in ("low", "medium", "high", "critical"):
        stats.append(
            AggregateStat(
                name="incidents_by_severity",
                label=severity,
                count=severity_counts[severity],
            )
        )

    approved = sum(
        action.approval_status in {ApprovalStatus.APPROVED, ApprovalStatus.AUTO_APPROVED}
        for action in actions
    )
    rejected = sum(action.approval_status is ApprovalStatus.REJECTED for action in actions)
    stats.extend(
        [
            AggregateStat(name="response_approval", label="approved", count=approved),
            AggregateStat(name="response_approval", label="rejected", count=rejected),
        ]
    )
    executed = [
        action
        for action in actions
        if action.execution_status is ExecutionStatus.SIMULATED and action.result is not None
    ]
    real_count = sum(_is_real_execution(action) for action in executed)
    stats.extend(
        [
            AggregateStat(name="response_execution", label="real", count=real_count),
            AggregateStat(
                name="response_execution",
                label="simulated",
                count=len(executed) - real_count,
            ),
        ]
    )
    return stats


def _rank_entities(
    events: Sequence[NormalizedEvent],
    event_types: set[NormalizedEventType],
    entity_type: EntityType,
    name: str,
    limit: int,
) -> list[AggregateStat]:
    counts: Counter[str] = Counter()
    labels: dict[str, str] = {}
    for event in events:
        if event.event_type not in event_types:
            continue
        event_entities: dict[str, str] = {}
        for entity in (event.primary_entity, *event.related_entities):
            if entity.entity_type is not entity_type:
                continue
            key = _entity_key(entity)
            event_entities.setdefault(key, entity.display_name)
        for key, label in event_entities.items():
            counts[key] += 1
            labels.setdefault(key, label)
    ordered = sorted(counts, key=lambda key: (-counts[key], labels[key].casefold(), key))[:limit]
    return [
        AggregateStat(
            name=name,
            label=labels[key],
            count=counts[key],
            entity=entity_type.value,
            rank=rank,
        )
        for rank, key in enumerate(ordered, start=1)
    ]


def _entity_key(entity: NormalizedEntity) -> str:
    return entity.display_name.casefold()


async def _latest_actions(
    approvals: ApprovalStore, incidents: Sequence[Incident]
) -> list[ActionAuditRecord]:
    by_id: dict[UUID, ActionAuditRecord] = {}
    for incident in incidents:
        for action in await approvals.list_for_incident(incident.id):
            by_id[action.id] = action
    return list(by_id.values())


def _action_timestamp(action: ActionAuditRecord) -> datetime:
    return action.decided_at or action.requested_at


def _is_real_execution(action: ActionAuditRecord) -> bool:
    return action.result is not None and action.result.details.get("mode") == "real"


def _in_window(timestamp: datetime, period_start: datetime, period_end: datetime) -> bool:
    return period_start <= timestamp < period_end


def _build_narrative_prompt(
    aggregate_stats: Sequence[AggregateStat], incidents: Sequence[Incident]
) -> str:
    facts = [stat.model_dump(mode="json") for stat in aggregate_stats]
    incident_summaries = [
        {
            "id": str(incident.id),
            "title": incident.title,
            "summary": incident.summary,
            "severity": incident.severity.value,
            "risk_score": incident.risk_score,
            "status": incident.status.value,
        }
        for incident in incidents
    ]
    return (
        "Write a concise daily security narrative from these supplied facts.\n"
        f"Aggregate statistics: {json.dumps(facts, sort_keys=True)}\n"
        f"Incidents: {json.dumps(incident_summaries, sort_keys=True)}"
    )
