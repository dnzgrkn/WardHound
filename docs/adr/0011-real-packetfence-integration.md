# ADR 0011: Safety-gated real PacketFence quarantine

- Status: Accepted
- Date: 2026-07-14

## Context

WardHound's response handlers originally produced audit descriptions without changing external
systems. Device quarantine is a high-value response, but it can also interrupt legitimate network
access. PacketFence is already a supported evidence source and exposes a node deregistration API,
making it the narrowest useful place to establish a real SOAR boundary.

The response handler Protocol was synchronous because simulation needed no I/O. Hiding an HTTP
request behind that signature would block FastAPI's event loop or require the same thread-and-event-
loop shim removed from the persistent stores in ADR 0009's amendment.

## Decision

### Async handler boundary

`SimulatedActionHandler.simulate` becomes asynchronous and `ResponseEngine` awaits it. All eight
handlers implement the async Protocol; the seven handlers without integrations still return their
existing simulation result without I/O. The name remains for compatibility with the established
extension point, while audit `details.mode` is the authoritative simulation-versus-real label.

The PacketFence client uses `httpx.AsyncClient` with a ten-second timeout. It calls PacketFence's
documented single-item form of `POST /api/v1/nodes/bulk_deregister` with the device MAC. PacketFence
deregistration removes registered access so enforcement can place the node in isolated access. The
API token is sent in PacketFence's documented `Authorization` header and is never logged or stored
in an audit record.

### Two-signal execution gate

A quarantine call is real only when both conditions hold:

1. `PACKETFENCE_BASE_URL` and `PACKETFENCE_API_TOKEN` are non-empty; and
2. `PACKETFENCE_REAL_EXECUTION` is exactly `true` after case normalization.

Every other configuration follows the original simulation path and description. Credentials can
therefore be validated or staged while mutation remains independently disabled. Approval and Auth0
authorization from ADR 0010 remain required before the handler is invoked; the flag does not bypass
either control.

Successful real calls retain `mode=real`, HTTP status, the returned node status when present, and a
boolean confirmation that is true only when PacketFence reports `unreg`. Simulation retains
`mode=simulation`. Timeout, connection, and non-success HTTP outcomes become failed execution audit
snapshots with `mode=real`; they do not escape the approval endpoint as unhandled exceptions. Full
response bodies are deliberately excluded because they can contain operational details.

### Deliberately narrow scope

Only `QUARANTINE_DEVICE` targets PacketFence. Implementing all eight integrations together would
multiply credentials, vendor failure modes, rollback requirements, and blast radius before this
safety boundary had been exercised. Active Directory, firewall, JumpServer, MFA, notification,
incident creation, and manual-checkpoint handlers remain simulations.

## Consequences

The zero-configuration demo is unchanged: absent PacketFence settings, quarantine produces the
same simulated audit result and makes no network request. Real mode creates a consequential external
side effect and depends on PacketFence availability and enforcement configuration. Operators must
use a dedicated least-privilege API identity restricted to node deregistration when PacketFence API
roles permit it, protect and rotate the token, and test against non-production nodes first.

The existing `ExecutionStatus.SIMULATED` enum remains the coarse successful-handler state because
schema changes are outside this stage. Consumers must use `result.details.mode` to distinguish real
from simulated success; the API and persisted audit payload always include that explicit label.
