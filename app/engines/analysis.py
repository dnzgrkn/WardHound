"""On-demand, structured Anthropic analysis of correlated incidents."""

from __future__ import annotations

import json
import os
from collections.abc import Sequence
from typing import Literal, Protocol, TypedDict, cast

import anthropic
import instructor

from app.schemas.analysis import RootCauseAnalysis
from app.schemas.events import NormalizedEvent
from app.schemas.incidents import Incident

DEFAULT_ANALYSIS_MODEL = "claude-sonnet-5"
DEFAULT_MAX_TOKENS = 2048
DEFAULT_MAX_RETRIES = 2

SYSTEM_PROMPT = """You are WardHound's enterprise security root-cause analyst.
Return only the requested RootCauseAnalysis structure. Explain and correlate evidence; never emit
shell commands, scripts, API calls, or instructions that autonomously change a system. Cite only
event UUIDs present in the supplied evidence. Use the ResponseActionType vocabulary. Every action
that changes security state must require human approval. Calibrate confidence to evidence quality,
and describe operational side effects even when the recommendation appears safe.

Synthetic domain examples:

1. PacketFence NAC isolation chain
Incident: repeated 802.1X authentication failures for CORP\\jdoe followed by isolation of
AA:BB:CC:DD:EE:FF and VLAN 999 assignment. Evidence includes PacketFence AUTH_FAILED event
11111111-1111-4111-8111-111111111111 and DEVICE_QUARANTINED event
11111111-1111-4111-8111-111111111112.
Analysis: probable cause is a device failing enterprise authentication and being isolated by NAC;
cite both events, use moderate-to-high confidence, recommend NOTIFY_ADMINISTRATOR and optionally
QUARANTINE_DEVICE with approval. Note that quarantine may interrupt legitimate connectivity.

2. JumpServer privileged-session anomaly
Incident: CORP\\jdoe opened a session to SRV-T0-0042 from 10.20.30.40, then JumpServer rejected a
policy-sensitive command. Evidence includes SESSION_STARTED event
22222222-2222-4222-8222-222222222221 and SESSION_ANOMALY_DETECTED event
22222222-2222-4222-8222-222222222222.
Analysis: probable cause is attempted privileged activity blocked by PAM policy; cite both events,
recommend CLOSE_SESSION and REQUIRE_MANUAL_APPROVAL with approval. Note that closing the session
can interrupt an authorized administrative task.

3. Active Directory account lockout
Incident: multiple AD AUTH_FAILED events culminated in ACCOUNT_LOCKED_OUT for CORP\\asmith from
WKSTN-0042. Evidence includes AUTH_FAILED event 33333333-3333-4333-8333-333333333331 and lockout
event 33333333-3333-4333-8333-333333333332.
Analysis: probable cause is repeated invalid credentials, while acknowledging stale credentials or
password spraying as alternatives; recommend REQUIRE_MFA with approval and NOTIFY_ADMINISTRATOR.
Note that identity controls may block legitimate access until ownership is confirmed.
"""


class AnalysisMessage(TypedDict):
    """Minimal message shape shared by the adapter and test doubles."""

    role: Literal["user", "assistant"]
    content: str


class AnalysisClient(Protocol):
    """Provider-neutral async client required by the analysis engine."""

    async def create_analysis(
        self,
        *,
        model: str,
        max_tokens: int,
        system: str,
        messages: list[AnalysisMessage],
        max_retries: int,
    ) -> RootCauseAnalysis:
        """Return one validated root-cause analysis."""
        ...


class _InstructorMessages(Protocol):
    async def create(
        self,
        *,
        response_model: type[RootCauseAnalysis],
        model: str,
        max_tokens: int,
        system: str,
        messages: list[AnalysisMessage],
        max_retries: int,
    ) -> RootCauseAnalysis: ...


class InstructorAnalysisClient:
    """Small adapter around Instructor's async Anthropic messages client."""

    def __init__(self, messages_client: _InstructorMessages) -> None:
        self._messages_client = messages_client

    async def create_analysis(
        self,
        *,
        model: str,
        max_tokens: int,
        system: str,
        messages: list[AnalysisMessage],
        max_retries: int,
    ) -> RootCauseAnalysis:
        return await self._messages_client.create(
            response_model=RootCauseAnalysis,
            model=model,
            max_tokens=max_tokens,
            system=system,
            messages=messages,
            max_retries=max_retries,
        )


class AnalysisError(RuntimeError):
    """Base exception callers can catch for all analysis-layer failures."""


class AnalysisConfigurationError(AnalysisError):
    """Raised when a real provider client cannot be configured."""


class AnalysisInputError(AnalysisError):
    """Raised before provider invocation when incident evidence is incomplete."""


class AnalysisGenerationError(AnalysisError):
    """Raised when provider or Instructor generation/validation fails."""


class AIAnalysisEngine:
    """Generate one structured analysis only when explicitly requested by a caller."""

    def __init__(
        self,
        client: AnalysisClient,
        *,
        model: str = DEFAULT_ANALYSIS_MODEL,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        max_retries: int = DEFAULT_MAX_RETRIES,
    ) -> None:
        if not model:
            raise ValueError("Analysis model must be non-empty")
        if max_tokens <= 0:
            raise ValueError("Analysis max_tokens must be positive")
        if max_retries < 0:
            raise ValueError("Analysis max_retries cannot be negative")
        self.client = client
        self.model = model
        self.max_tokens = max_tokens
        self.max_retries = max_retries

    async def analyze(
        self, incident: Incident, evidence: Sequence[NormalizedEvent]
    ) -> RootCauseAnalysis:
        """Analyze an incident using focused normalized evidence and no raw payloads."""
        evidence_by_id = {event.id: event for event in evidence}
        missing = set(incident.event_ids).difference(evidence_by_id)
        if missing:
            raise AnalysisInputError("Incident evidence is missing one or more referenced events")
        messages = [
            AnalysisMessage(role="user", content=_build_incident_prompt(incident, evidence))
        ]
        try:
            analysis = await self.client.create_analysis(
                model=self.model,
                max_tokens=self.max_tokens,
                system=SYSTEM_PROMPT,
                messages=messages,
                max_retries=self.max_retries,
            )
        except Exception as exc:
            raise AnalysisGenerationError(
                "AI analysis generation or structured validation failed"
            ) from exc
        cited_ids = {item.event_id for item in analysis.evidence}
        if not cited_ids.issubset(evidence_by_id):
            raise AnalysisGenerationError("AI analysis cited evidence outside the supplied events")
        return analysis


def create_analysis_engine_from_env() -> AIAnalysisEngine:
    """Construct the real Anthropic/Instructor integration only on explicit invocation."""
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise AnalysisConfigurationError("ANTHROPIC_API_KEY is required for real AI analysis")
    model = os.getenv("WARDHOUND_ANALYSIS_MODEL", DEFAULT_ANALYSIS_MODEL)
    if not model:
        raise AnalysisConfigurationError("WARDHOUND_ANALYSIS_MODEL must be non-empty")
    anthropic_client = anthropic.AsyncAnthropic(api_key=api_key)
    structured_client = instructor.from_anthropic(anthropic_client)
    adapter = InstructorAnalysisClient(cast(_InstructorMessages, structured_client.messages))
    return AIAnalysisEngine(client=adapter, model=model)


def _build_incident_prompt(incident: Incident, evidence: Sequence[NormalizedEvent]) -> str:
    policy_rules = [violation.rule_id for violation in incident.policy_violations]
    event_lines = "\n".join(_format_event(event) for event in evidence)
    return (
        "Analyze this correlated WardHound incident.\n"
        f"Incident ID: {incident.id}\n"
        f"Title: {incident.title}\n"
        f"Summary: {incident.summary}\n"
        f"Severity: {incident.severity.value}\n"
        f"Risk score: {incident.risk_score:.1f}/100\n"
        f"Correlation rule: {incident.correlation_rule_id}\n"
        f"Policy violations: {', '.join(policy_rules) if policy_rules else 'none'}\n"
        "Evidence:\n"
        f"{event_lines}"
    )


def _format_event(event: NormalizedEvent) -> str:
    related = ", ".join(entity.display_name for entity in event.related_entities) or "none"
    attributes = _focused_attributes(event)
    return (
        f"- event_id={event.id}; source={event.source_system.value}; "
        f"type={event.event_type.value}; severity={event.severity.value}; "
        f"occurred_at={event.occurred_at.isoformat()}; "
        f"primary_entity={event.primary_entity.display_name}; related_entities={related}; "
        f"attributes={attributes}"
    )


def _focused_attributes(event: NormalizedEvent) -> str:
    focused = {key: str(value)[:200] for key, value in sorted(event.extra_attributes.items())[:8]}
    return json.dumps(focused, sort_keys=True)
