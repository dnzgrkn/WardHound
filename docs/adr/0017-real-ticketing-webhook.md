# ADR 0017: Safety-gated external ticketing webhook

- Status: Accepted
- Date: 2026-07-15

## Context

`CreateIncidentHandler` does not create WardHound's own incident. That incident already exists
before response recommendations run. The handler represents opening a separate tracking record in
an external ITSM or ticketing system so teams outside WardHound can coordinate work.

Directly selecting ServiceNow, Jira, or another vendor would couple WardHound to one authentication
model and payload schema. Real deployments can instead place a small, deployment-owned webhook in
front of their chosen system. WardHound needs only that URL and a minimal vendor-neutral contract.

Like administrator notification, ticket creation is a low-risk real integration because it does
not mutate NAC, directory, firewall, PAM, or identity state. Its credible operational failures are
a spurious or missing tracking ticket. Its main security risk is the new data-egress path and
exposure of the webhook URL, which commonly embeds a bearer-token-equivalent secret.

## Decision

### Separate client and bounded contract

`TicketingClient` is separate from the administrator-notification client and uses independent
configuration. It posts a JSON object containing `title`, `description`, `incident_id`, and
`severity` through `httpx.AsyncClient` with an explicit ten-second timeout. The description is a
whitespace-normalized recommendation rationale capped at 1,000 characters; no normalized evidence,
raw event payload, entity data, credential, or webhook URL is included.

The response-handler contract does not carry the persisted incident title, so the handler builds a
deterministic title from the WardHound incident ID. `ActionContext` carries the linked incident's
persisted severity, which is sent without expanding the payload's data boundary. Unlinked response
requests retain the honest `unknown` fallback rather than fabricating a severity.

### Confirmation and failure semantics

HTTP acceptance alone does not prove that the webhook created a tracking record. A successful 2xx
response must contain a non-empty string `ticket_id`. The returned identifier and HTTP status are
recorded in the audit because the identifier is useful for cross-system follow-up and is not a
credential. Timeout, connection, non-2xx, invalid JSON, and missing or blank ticket identifiers
become clean failed execution snapshots through `ActionExecutionError`.

This differs slightly from infrastructure confirmation reads. The webhook's creation response is
the vendor-neutral confirmation artifact; a separate read would require vendor-specific API
knowledge and credentials that this boundary intentionally avoids.

### Two-signal gate and honest audit

Real ticket creation requires both a non-empty `TICKETING_WEBHOOK_URL` and
`TICKETING_REAL_EXECUTION=true` after whitespace trimming and case normalization. Every other
configuration stays on the no-network simulation path.

Real success and failure use `integration=ticketing`, `operation=create_ticket`, and `mode=real`.
Simulation uses the same integration and operation with `mode=simulation`. The secret URL and
response body are never logged or retained.

## Consequences

With both ticketing variables absent, the demo remains unchanged and makes no ticketing request.
With the gate enabled, a deployment can create cross-team tracking records without embedding
vendor-specific behavior in WardHound. Operators must store and rotate the URL like an API token,
restrict process-environment access, and restrict egress to the intended webhook host.

A returned ticket identifier confirms record creation according to the webhook contract, not that
an assignee read or acted on it. Automatic retries are deliberately absent because an unkeyed
retry could create duplicate tickets. Durable delivery, idempotency keys, and reconciliation are
future deployment concerns.
