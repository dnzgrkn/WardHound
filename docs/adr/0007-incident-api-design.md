# ADR 0007: Incident dashboard API design

- Status: Accepted
- Date: 2026-07-13

## Context

Stages 3 through 5 established independently testable correlation, policy, risk, AI analysis, and
simulated response engines. None has an HTTP surface. Stage 6's dashboard needs a way to submit
normalized demo evidence, browse incidents, request analysis, make approval decisions, and receive
realtime updates without moving business rules into FastAPI routes.

The repository has PostgreSQL and Redis clients for health checks, but it does not yet have event,
incident, analysis, or action tables and migrations. Requiring that infrastructure for the first
dashboard slice would couple API design to a premature persistence model and make the end-to-end
demo harder to run. Approval state already demonstrates the project's small-protocol and in-memory
implementation pattern.

The product specification lists JWT authentication, while WardHound currently has no user
directory, roles, token issuer, or frontend login flow. Leaving response approvals entirely
unauthenticated would still be an unsafe default even for a single-operator demonstration.

## Decision

### Store ports and persistence deferral

Stage 6a introduces two synchronous persistence protocols:

- `EventStore.add_all` retains immutable normalized events by UUID, and `get_many` recovers evidence
  in incident event-ID order.
- `IncidentStore.upsert`, `get`, and `list_all` retain incidents, while `save_analysis` and
  `get_analysis` associate the latest on-demand `RootCauseAnalysis` with an incident UUID.

Separate stores match the existing model: an incident references normalized event UUIDs instead of
embedding evidence. They also map naturally to separate future event, incident, and analysis tables.
The supplied implementations are in-memory dictionaries and are injected through FastAPI's service
dependency alongside the existing `ResponseEngine` and an analysis-engine factory.

No route imports SQLAlchemy or opens a database connection. A future repository can implement the
same ports while preserving endpoint and engine composition. The current stores do not survive a
restart, coordinate multiple workers, or provide transactions, pagination, retention, or database
query optimization. Those are explicit deferrals, not production persistence claims.

### Endpoint composition

`POST /api/v1/events` accepts already-normalized events, retains them, calls the existing
`run_pipeline`, and upserts its returned incidents. It does not repeat correlation, policy, or risk
logic. Incident list and detail routes read the stores and provide only explicit severity/status
filters and created-time/risk-score sorting.

Analysis remains on demand. The analysis endpoint loads the retained incident and evidence, obtains
an injected `AIAnalysisEngine`, calls `analyze`, and stores the typed result. Missing provider
configuration, invalid evidence, and generation failures become stable typed HTTP error payloads
instead of provider exceptions or generic 500 responses.

Action routes load the incident and evidence, use the existing `action_context_from_incident`, and
delegate requests and decisions to `ResponseEngine`. Its not-found and invalid-transition
exceptions map to HTTP 404 and 409. The API never changes the response engine's privileged approval
gate or simulation-only handlers.

### Authentication placeholder

Every `/api/v1` REST route requires a static `X-API-Key` value matching `WARDHOUND_API_KEY` using a
constant-time comparison. Missing server configuration fails closed with HTTP 503; a missing or
incorrect client key returns HTTP 401. `/health` remains unauthenticated so infrastructure probes
can use it.

Browser WebSocket clients cannot set an arbitrary `X-API-Key` header, so the realtime endpoint
accepts the same key through the `api_key` query parameter and rejects invalid connections with
WebSocket policy-violation code 1008. TLS is mandatory outside local development because query
parameters may appear in client or proxy logs.

This key is a deliberate single-operator placeholder. Every holder has the same authority, there is
no expiry or rotation protocol, and `decided_by` remains a caller-supplied audit label rather than a
verified identity. Full authentication requires an identity provider, signed short-lived JWT access
tokens, issuer/audience validation, role claims separating viewers, analysts, and approvers,
revocation/refresh policy, and deriving the decision maker from authenticated claims. WebSocket
authentication should then use a short-lived connection token or secure cookie rather than the
static query key.

### Realtime updates

The WebSocket message contract is a Pydantic `RealtimeMessage` with a closed type vocabulary:
`incident_created`, `incident_updated`, or `action_updated`. Its payload is the corresponding typed
`Incident` or `ActionAuditRecord`. The ingestion endpoint distinguishes creation from deterministic
UUID upsert; analysis emits an incident update; action request, approval, and rejection emit action
updates.

`IncidentConnectionManager` retains active WebSocket objects in the application process and sends
the serialized typed message to each connection. Redis pub/sub is deferred because Stage 6a runs as
one API process and needs no cross-worker fan-out. When the application runs multiple workers or
instances, a Redis channel (or equivalent broker) must distribute messages to each process-local
connection manager, with delivery and backpressure behavior defined explicitly.

## Consequences

Stage 6b can populate and operate the dashboard through a versioned API without live collectors,
PostgreSQL migrations, Redis messaging, or real remediation integrations. The HTTP layer remains a
composition boundary over existing typed engines, and tests can replace stores and analysis clients
without network calls.

State and WebSocket reach are process-local, the static key is not user authentication, and list
operations are in-memory scans. These limitations are acceptable for the current single-operator
portfolio demo and must be replaced before a multi-user or multi-process deployment.
