# ADR 0009: Persistent data layer

- Status: Accepted
- Date: 2026-07-14

## Context

WardHound's engine boundaries deliberately accept typed event collections and expose small store
protocols without database concerns. The Stage 6 dashboard implementations retained normalized
events, incidents, analyses, and response audit snapshots in process memory. PostgreSQL and an
`AsyncEngine` were already part of the runtime, but application state did not survive an API
restart.

## Decision

### Schema management

Alembic manages versioned PostgreSQL schema changes because it is SQLAlchemy's established
migration companion, can compare the ORM metadata when future revisions are generated, and runs
through the project's existing asyncpg connection URL. Starting the API container runs `alembic
upgrade head` before Uvicorn, and CI applies the same migration explicitly before tests. This keeps
fresh Compose databases and upgraded persistent volumes on one reproducible path. Handwritten SQL
would provide more direct control but would duplicate SQLAlchemy type definitions and require a
custom revision runner.

### Storage shape

Three tables retain normalized events, incidents, and append-only response action audit snapshots.
The stable UUIDs, occurrence/creation times, incident links, and audit sequence are relational
columns used for identity, ordering, and indexes. Canonical Pydantic payloads—including entities,
event IDs, extra attributes, policy violations, action context, and simulation results—use JSONB.
The incident table also holds the latest `RootCauseAnalysis` as nullable JSONB.

JSONB avoids duplicating and synchronizing the existing nested Pydantic contracts across many
premature join tables, while PostgreSQL still validates the relational keys needed by repository
operations. The cost is weaker database-level validation inside payloads and less efficient
field-level analytics. If query requirements expand beyond IDs and timestamps, frequently filtered
fields should be promoted to typed columns or normalized tables through later migrations.

### Repository and session lifecycle

The application creates one shared `AsyncEngine`; each repository operation creates and closes its
own `AsyncSession` and commits writes before returning. Sessions are therefore operation-scoped,
not request-scoped, because the inherited store protocols and `ResponseEngine` are synchronous and
one response transition may append more than one independently auditable snapshot. No session is
held in global application state.

The synchronous Stage 6 ports are preserved so engine and isolated unit-test contracts remain
unchanged. PostgreSQL adapters bridge each operation to async SQLAlchemy work. The engine uses
`NullPool`, preventing asyncpg connections from crossing the API loop and the compatibility
bridge's worker loop; PostgreSQL remains responsible for connection concurrency. Native async store
ports and request-level transaction composition are a follow-up if atomic operations must span
multiple repositories. This compatibility cost is preferred here to changing engine contracts in
a persistence-only stage.

### Correlation history scaling

`EventStore.get_all()` deliberately retains Stage 6a semantics: every ingestion re-reads all stored
events so a correlation chain can span requests. This is correct for the current MVP but is not a
production-volume query strategy. Retention policies, indexed time-range reads based on the largest
configured correlation window, pagination, and incremental correlation checkpoints are explicitly
deferred. PostgreSQL persistence makes that scaling work visible; it does not make an unbounded
full-history scan acceptable at large event volume.

## Consequences

Events, incidents, retained analyses, and response action history survive API process restarts and
fresh repository construction. The existing in-memory stores remain available for fast isolated
tests. Deployments must run migrations before serving traffic; the supplied Compose command and CI
workflow enforce that ordering. JSONB payload changes remain governed by the Pydantic contracts and
may require data migrations when a future schema change is not backward compatible.

## Amendment (native async store protocols)

The event, incident, and approval store protocols and their in-memory implementations are now
native async interfaces. `ResponseEngine` and the FastAPI composition layer await every store
operation, and PostgreSQL repositories open their operation-scoped `AsyncSession` directly on the
request's event loop. The compatibility bridge described above—per-call worker threads, nested
event loops, and `NullPool` as protection against cross-loop connection reuse—has been removed.

This correction preserves operation-scoped sessions and independently committed response audit
snapshots while preventing database round trips from blocking unrelated HTTP requests, WebSocket
work, and health checks. `NullPool` remains a deployment choice in the application wiring, not an
async correctness requirement; adopting a bounded shared pool can be evaluated separately with
production concurrency and connection-budget measurements.
