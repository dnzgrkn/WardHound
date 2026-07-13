# ADR 0006: Simulated response engine design

- Status: Accepted
- Date: 2026-07-13

## Context

Stage 5 is the first WardHound stage that models a response after analysis. The response vocabulary
and its schema-level approval rule already live in `app/schemas/analysis.py`: actions that could
alter NAC, directory, firewall, PAM, or identity state must require approval. The response engine
must turn those recommendations into a durable human decision workflow without weakening that
boundary.

Unlike correlation, policy, risk, and on-demand analysis, approval cannot complete within one
function call. A request can be submitted in one process and approved or rejected later by a future
dashboard API request in another process. Stage 5 therefore needs a persistence boundary even
though it must not import SQLAlchemy, open a database connection, or require infrastructure in its
tests.

`RecommendedAction` identifies an action type and rationale but deliberately contains no concrete
MAC address, account, IP address, or session identifier. Simulated handlers still need an auditable
target to describe what a real integration would have attempted.

## Decision

### Response contracts

Response-specific contracts live in `app/schemas/response.py`, separate from the AI analysis
contracts. The analysis schema remains the provider-facing structured-output boundary, while the
response schema consumes its existing `ResponseActionType` and `RecommendedAction` definitions
without duplicating their closed vocabulary or privileged-action validator.

`ActionAuditRecord` contains the originating recommendation, optional incident ID, persisted target
context, approval decision fields, execution status and result, and request time. The model is
frozen. Approval, rejection, and simulated execution use `model_copy` to produce new snapshots
rather than mutating an earlier record.

`ApprovalStatus` distinguishes pending, approved, rejected, and automatically approved requests.
`ExecutionStatus` distinguishes requests that never ran, successful simulations, and failed
simulations. Failure is a meaningful outcome: for example, a quarantine simulation fails when the
incident context has no device MAC address instead of reporting a successful placeholder.

### Approval store seam and lifecycle

The engine depends on a small synchronous `ApprovalStore` protocol:

- `append(record)` adds an immutable lifecycle snapshot;
- `get(record_id)` returns the latest snapshot; and
- `history(record_id)` returns the append-ordered audit history; and
- `list_for_incident(incident_id)` returns the latest snapshot of each request linked to an
  incident.

The Stage 5 implementation is an in-memory dictionary whose values are snapshot lists. All tests
use it. A future SQLAlchemy repository can implement the same protocol with an append-only table,
latest-record query, and incident-indexed latest-snapshot query without changing response-engine
decisions or handlers. Synchronous methods
keep this in-memory engine simple; a future asynchronous API boundary can adapt database calls or
revise the port when the actual persistence architecture exists.

A privileged request is stored as `PENDING` and is never passed to a handler until `approve` records
an identified human decision. Rejection appends a `REJECTED` snapshot and never executes. A
non-privileged request with `requires_approval=false` is recorded as `AUTO_APPROVED` and immediately
simulated. The engine independently checks membership in `RecommendedAction.PRIVILEGED_ACTIONS`
before auto-approval, so a caller cannot bypass the gate by supplying an invalid constructed model.

### Target context

`ActionContext` is stored with the request because an approval may occur after the caller releases
the incident and evidence objects. `action_context_from_incident` snapshots the incident's normalized
entities and extracts a non-empty `session_id` only from normalized events referenced by that
incident. Device, account, and IP handlers select the matching typed entity; the session handler
uses the evidence-derived session identifier. This avoids placing environment-specific target data
inside AI recommendations while retaining enough information for a later approval process.

The caller is responsible for loading the incident and its normalized evidence through the future
repositories before requesting an action. Stage 5 performs no database lookup itself.

### Handler registry

Simulated handlers implement a small protocol and are registered by `ResponseActionType`, matching
the concrete-rule registry pattern used by the correlation and policy engines. The default registry
contains one handler for each of the eight action types. Adding or replacing a handler does not
change the approval workflow.

Handlers return a human-readable description, a target identifier, and structured integration,
operation, and simulation-mode details. Notification and incident-creation handlers describe
logging or tracking activity rather than pretending to mutate a security control.

### Simulation boundary

"Simulated" means the engine writes only its own audit snapshots and returns a description of a
hypothetical integration call. Handlers do not import or call PacketFence, Active Directory,
JumpServer, firewall, identity-provider, notification, or incident-management clients. They make no
network request and cause no external system mutation. No action is autonomously remediated.

Making an action real would require a separately reviewed integration adapter for the relevant
system, credential and secret handling, timeouts and retry/idempotency policy, authorization,
observability, and explicit production configuration selecting that adapter. The human approval
gate and audit-store contract would remain in front of it. Merely changing a status label or adding
credentials to the existing simulated handlers is not sufficient to cross this scope boundary.

## Consequences

Approval requests can survive beyond one engine call through a replaceable store contract, while
the current implementation and test suite remain infrastructure-free. Every lifecycle transition
is reviewable as an immutable snapshot, and handlers receive targets that remain available when a
later decision is made. All response action types produce specific audit descriptions, and missing
targets are visible as failed simulations.

The in-memory store does not survive process restart, coordinate concurrent writers, authenticate
decision makers, or provide retention and query policy. Context extraction recognizes only the
current normalized entities and `session_id` evidence convention. Those capabilities belong to the
Stage 6 API/authentication and future persistent repository and integration work.
