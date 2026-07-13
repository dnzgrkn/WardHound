# ADR 0005: AI analysis engine design

- Status: Accepted
- Date: 2026-07-13

## Context

Stage 4 adds the first cost-bearing and externally hosted component to WardHound. It must turn a
correlated incident and its normalized evidence into an explainable root-cause assessment without
weakening the deterministic safety boundaries established by the earlier stages. The AI may explain,
cite evidence, estimate confidence, and recommend typed responses. It may not generate commands,
execute responses, or return unvalidated prose.

Anthropic model identifiers and availability change independently of WardHound releases. Provider
responses can also fail schema validation, exhaust retries, or cite evidence that was not supplied.
Tests and imports must work without an API key and must never make a real provider request.

## Decision

### Structured output through Instructor

The engine requests `RootCauseAnalysis` directly through Instructor with Pydantic validation.
Instructor is used instead of raw JSON mode or manual parsing because it binds the provider response
to the application schema, supplies validation feedback during bounded retries, and avoids a second
handwritten parser whose behavior could drift from the Pydantic contract. The engine never exposes
raw assistant prose as an analysis result.

The schema references evidence by normalized event UUID rather than embedding complete events.
After Instructor returns a valid model, the engine also verifies that every cited UUID belongs to
the supplied evidence collection. Provider failures, exhausted validation retries, and invalid
citations are translated into `AnalysisGenerationError`, giving future API code one stable exception
boundary instead of leaking provider-specific failures.

### On-demand invocation and dependency injection

Analysis is an explicit, on-demand async operation and is not added to Stage 3's `run_pipeline`.
Correlation and deterministic risk scoring remain fast, offline, and free of token cost. A caller can
choose which incident merits analysis, apply rate limits, retry later, or display an incident before
an AI assessment exists.

`AIAnalysisEngine` depends on a small async client protocol. Production construction wraps
`instructor.from_anthropic(anthropic.AsyncAnthropic(...))` in an adapter; tests inject small fakes.
`ANTHROPIC_API_KEY` is read only by the explicit production factory. Importing schemas or the engine,
constructing an engine with a fake, and running the entire test suite require no key.

### Model and cost controls

The model comes from `WARDHOUND_ANALYSIS_MODEL`, with `claude-sonnet-5` as the documented default.
Sonnet is the default because analysis needs reliable multi-source reasoning while remaining more
cost-conscious than selecting the most capable model unconditionally. Operators can change the
model without a code release when availability, quality, or pricing changes.

Output is capped at 2,048 tokens and structured-validation retries are capped at two. Both are
constructor parameters for controlled experiments and future configuration, but they always have
finite defaults.

### Focused prompting and few-shot examples

The incident prompt contains its title, summary, severity, risk score, correlation rule, policy rule
identifiers, and concise normalized event fields. Event type, source, severity, time, primary and
related entity display names, and a bounded selection of extra attributes are included. Raw source
payloads are not sent because they add noise, increase token cost, and may contain data unrelated to
the incident.

The system prompt includes three synthetic examples aligned to WardHound's actual domains:

- a PacketFence 802.1X failure, isolation, and quarantine-VLAN chain;
- a JumpServer privileged session followed by a PAM command-policy anomaly; and
- Active Directory authentication failures culminating in account lockout.

These examples teach the model how WardHound's NAC/PAM/AD event names relate without inserting any
client data. General-purpose models have broad security knowledge but weaker priors about this
project's normalized event vocabulary, PacketFence Person ID/device distinction, and JumpServer
session semantics. Domain examples therefore improve evidence selection and action calibration more
directly than generic incident-response examples.

### Approval contract

`RecommendedAction.requires_approval` remains visible on every recommendation because Stage 5 and
operators need an explicit per-request decision. It is not trusted as an unconstrained model choice.
The schema rejects `false` for actions that alter security state: quarantine device, disable user,
block IP, close session, require MFA, and require manual approval. Notification and incident creation
may be marked as not requiring approval, while the model may still choose the conservative `true`
value for them. This preserves structured model intent while enforcing the platform's human-in-the-
loop invariant in code.

### Test isolation

Tests inject clients that either return a fixed `RootCauseAnalysis` or simulate exhausted validation
retries. They assert prompt construction, typed error translation, citation validation, confidence
bounds, evidence cardinality, and approval enforcement. A factory test removes
`ANTHROPIC_API_KEY` and confirms that only explicit real-client construction fails. No test patches
over a live network client or conditionally calls Anthropic when a developer happens to have a key.

## Consequences

AI analysis is typed, cited, bounded, and independently callable. Correlation and CI remain provider-
independent, and Stage 5 receives a closed response-action vocabulary with approval enforcement.
Changing models or injecting a test/evaluation client does not change analysis logic.

The engine does not cache analyses, schedule calls, track token usage, evaluate model quality, or
execute recommendations. Those concerns belong to later persistence, observability, API, and
response-engine stages.
