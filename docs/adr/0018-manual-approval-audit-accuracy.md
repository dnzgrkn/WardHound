# ADR 0018: Manual-approval audit accuracy

- Status: Accepted
- Date: 2026-07-15

## Context

`RequireManualApprovalHandler` used the description "Would record a satisfied manual-approval
checkpoint" and labeled its result as a simulation. That wording predates the persistent approval
store and Auth0 identity boundary.

By the time this handler runs, the meaningful action has already happened. `ResponseEngine.approve()`
accepts the verified Auth0 subject supplied by the authorized API layer, creates an approved
immutable snapshot with `decided_by` and `decided_at`, and awaits `ApprovalStore.append()` before
calling `_execute()`. The PostgreSQL adapter durably commits that snapshot in deployed operation;
the in-memory adapter preserves the same ordering in isolated tests.

There is no external manual-approval system waiting to be integrated. Describing this state as a
hypothetical future simulation makes the audit less accurate than the workflow it records.

## Decision

The `SimulatedActionHandler.simulate()` protocol receives optional keyword-only `decided_by` and
`decided_at` values. `ResponseEngine._execute()` passes both fields from the action snapshot already
in scope. All seven other handlers accept and ignore the new parameters; their decisions, network
behavior, descriptions, targets, and audit details are unchanged.

`RequireManualApprovalHandler` requires both decision fields and returns:

- `Manual approval checkpoint satisfied by {decided_by} at {decided_at}.`
- `integration=approval_audit`
- `operation=record_manual_checkpoint`
- `mode=real`

The mode is unconditionally real because it classifies the persisted approval the handler
describes, not an additional downstream operation. Missing decision metadata is an invalid handler
invocation and becomes a failed target result rather than producing an unattributed approval claim.

The method and `ExecutionStatus.SIMULATED` success enum retain their historical names because they
are shared compatibility surfaces and schemas are outside this correction. As with safety-gated
real integrations, `result.details.mode` is the authoritative classification.

## Why this is not another real integration

Stages 11–17 added outbound clients, credentials or secret URLs, execution gates, vendor failure
modes, and external confirmation semantics. This change adds none of those. It only carries data
that the engine already persisted across the existing handler abstraction so the final audit
description matches reality. No new trust boundary or external side effect is introduced.

## Consequences

Manual-approval results are attributable to the real approving principal and decision timestamp,
and no longer imply that another checkpoint still needs to be recorded. The protocol is slightly
wider, but it remains uniform and avoids a one-handler special case in `_execute()`.

An end-to-end engine test requests the privileged action, approves it with a synthetic Auth0-style
subject, and verifies that the persisted approved snapshot's identity and timestamp reach the real
default handler. Direct handler calls without decision metadata fail instead of creating misleading
audit text.
