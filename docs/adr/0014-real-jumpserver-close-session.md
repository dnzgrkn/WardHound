# ADR 0014: Safety-gated real JumpServer session termination

- Status: Accepted
- Date: 2026-07-14

## Context

WardHound's `CLOSE_SESSION` handler previously described terminating a privileged JumpServer
session without contacting JumpServer. Ending an active PAM session is consequential: it interrupts
the connected operator mid-task, but is reversible because an authorized operator can establish a
new session. Its blast radius is therefore narrower than Active Directory account disablement,
which can revoke access across every system that trusts the identity.

The initially plausible route `POST /api/v1/terminal/sessions/{id}/terminate/` is not present in
the current JumpServer v1 API. The official JumpServer source registers `KillSessionAPI` at
`terminal/tasks/kill-session/`. Its POST body is a JSON array of session IDs. The controller keeps
only existing, unfinished sessions, creates a task named `kill_session` for each, and returns the
accepted identifiers as `{"ok": [...]}`. A successful response therefore means task acceptance,
not proof that the session has ended.

## Decision

### Verified API contract and authentication

WardHound sends `POST /api/v1/terminal/tasks/kill-session/` with
`["<session-id>"]`, using JumpServer's documented permanent Private Token header
`Authorization: Token <token>`. This matches the low-volume service-integration configuration:
WardHound receives a dedicated token rather than storing an operator password to obtain a temporary
Bearer token or implementing Access Key request signing.

The client uses `httpx.AsyncClient`, an explicit ten-second timeout, and HTTPS-only base URLs. It
does not log or retain the API token. Timeout, connection, non-success HTTP, malformed response,
and task-rejection outcomes become bounded `JumpServerError` messages.

### Confirmation read

After JumpServer accepts the kill task, WardHound fetches
`GET /api/v1/terminal/sessions/{id}/` and reports success only when the returned object has the
expected ID and `is_finished` is exactly `true`. This is the same state field consumed by the
existing collector. A 2xx kill-task response followed by an active session is a failed execution,
not a successful audit record. This deliberately avoids confusing asynchronous task acceptance
with completed enforcement.

### Three-signal execution gate and audit

Real execution requires all three signals:

1. a non-empty `JUMPSERVER_BASE_URL`;
2. a non-empty `JUMPSERVER_API_TOKEN`; and
3. `JUMPSERVER_REAL_EXECUTION=true`.

Every partial or disabled configuration retains the original simulation result without creating a
client. The session ID remains a target precondition sourced from retained JumpServer evidence; a
missing ID still fails before this configuration gate. Human approval and Auth0 authorization
remain mandatory upstream.

Confirmed real results use `mode=real`, `operation=terminate_session`, and explicit
`termination_confirmed`/`is_finished` fields. Failed real attempts keep `mode=real` and a safe error
category so an infrastructure failure never escapes the approval endpoint or resembles simulation.

## Consequences

With no JumpServer variables, the demo and close-session handler behave exactly as before and make
no network request. With the gate enabled, approval can disrupt a live privileged operation, so the
token must belong to a dedicated identity with `terminal.terminate_session` and no broader
administrative permissions where JumpServer's RBAC permits. Operators must protect and rotate the
token, restrict WardHound egress to the management endpoint, and enable real execution only after
testing against non-production sessions.

The confirmation read is immediate. If JumpServer has accepted but not yet processed its
asynchronous task, WardHound fails closed rather than polling or claiming success. Bounded polling
and retry policy are deferred until operational timing data justifies them.

## Sources

- [JumpServer REST API authentication](https://docs.jumpserver.org/zh/v4/dev/rest_api/)
- [JumpServer terminal API URL registration](https://github.com/jumpserver/jumpserver/blob/dev/apps/terminal/urls/api_urls.py)
- [JumpServer kill-session controller](https://github.com/jumpserver/jumpserver/blob/dev/apps/terminal/api/session/task.py)

