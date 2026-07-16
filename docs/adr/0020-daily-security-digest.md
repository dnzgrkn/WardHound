# ADR 0020: Daily security digest core

- Status: Accepted
- Date: 2026-07-16

## Context

WardHound exposes correlated incidents, but most normalized security events do not meet a
correlation threshold and are therefore absent from the operator-facing incident view. Operators
need a bounded daily record that covers both correlated incidents and the underlying activity.
Later delivery stages also need a stable persisted shape that can be rendered or sent without
recomputing historical facts.

## Decision

### Stored model

`DailyDigest` records a timezone-aware half-open period, generation time, the existing typed
`Incident` objects created during that period, deterministic aggregate statistics, and an optional
typed `DigestNarrative`. Reusing `Incident` preserves the existing incident and risk fields instead
of creating a second summary contract that could drift. Each aggregate statistic has a stable name,
display label, non-negative count, and optional entity type and rank. This flat, bounded form can be
grouped by name by API clients and consumed directly by later PDF and email renderers.

The SQL model follows the incident persistence decision in ADR 0009: the UUID and generation time
are relational and indexed, while the canonical nested Pydantic record is JSONB. The digest store
is native async, and every PostgreSQL operation uses its own async session on the caller's event
loop. History orders by generation time descending, with UUID as a deterministic tie-breaker.

### Window and deterministic aggregation

Digest windows are half-open: `period_start <= timestamp < period_end`. Adjacent daily periods can
therefore meet at an exact boundary without omitting or double-counting activity. Events use
`occurred_at`, incidents use `created_at`, and response actions use `decided_at` when present or
`requested_at` for auto-approved/request-time records.

Counts and rankings are ordinary deterministic operations over normalized fields. The digest
includes failed-authentication users, devices involved in quarantine or unknown-device activity,
users involved in privileged commands or anomalous sessions, incidents by severity band, approval
decisions, and real-versus-simulated successful response executions. Entity rankings are sorted by
count with stable lexical tie-breaking and capped at ten. This approach is deliberately not learned:
there is no suitable labeled training set, daily counts must be reproducible, and operators must be
able to explain every displayed number from retained records. This follows the explainability
principle of ADR 0004's deterministic risk scoring.

### Optional AI narrative

Anthropic plus Instructor produces a typed `DigestNarrative` containing an executive summary,
highlights, and recommended follow-up items. The model receives only the already-computed aggregate
facts and incident summaries; it does not determine counts or rankings. Construction uses an
injected factory parallel to the on-demand incident analysis integration. When
`ANTHROPIC_API_KEY` is absent, factory configuration failure is treated as an expected degraded
mode: the digest is still built and persisted with all deterministic content and `narrative=None`.
Provider or structured-validation failures after a configured call remain visible errors rather
than being mistaken for an unconfigured deployment.

### API authorization boundary

Generating or reading a digest is a reporting operation over data WardHound already retains. It
does not approve a response or mutate external security infrastructure. Consequently,
`POST /api/v1/digests/generate`, `GET /api/v1/digests`, and `GET /api/v1/digests/{id}` remain behind
the existing static API key, consistent with ADR 0010's boundary between dashboard/report access
and Auth0-protected privileged infrastructure mutation. Manual generation persists an internal
report, but grants no response authority and causes no external side effect.

## Consequences

Operators can manually create and retrieve complete 24-hour activity summaries even when AI is not
configured. Aggregates are bounded and stable, and generated records are suitable as inputs to
future delivery mechanisms. Reading full event and incident history retains the existing MVP store
scaling limitation; indexed time-range store methods can replace that input strategy later without
changing the digest contract.

PDF export, email delivery, and daily scheduling are explicitly deferred to later stages. This
stage adds no renderer, mail integration, Celery task, or schedule.
