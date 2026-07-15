# ADR 0016: Safety-gated administrator webhook notification

- Status: Accepted
- Date: 2026-07-15

## Context

WardHound's administrator-notification handler previously recorded only a simulation. Sending a
small webhook message is the lowest-risk real integration added so far: it does not mutate NAC,
directory, firewall, PAM, or identity infrastructure. The credible operational failure is a
spurious or missing notification, while the main security risk is leaking sensitive incident data
or the webhook URL into an external channel or audit trail.

An incoming-webhook URL commonly embeds an unguessable token and is therefore a credential, not a
harmless endpoint address. It must remain environment-only and must never appear in logs, audit
records, error messages, or the request body.

## Decision

### Narrow webhook client and payload

`WebhookClient` uses `httpx.AsyncClient` with an explicit ten-second timeout and posts a
Slack Incoming Webhook-compatible `{"text": "..."}` JSON body. The message contains only an
incident ID (or an explicit unlinked label), severity, a whitespace-normalized rationale capped at
500 characters, and a UTC timestamp. It never receives normalized evidence, raw event payloads,
entities, credentials, or the webhook URL as message inputs.

The current response-handler contract does not carry incident severity and schemas are outside
this stage, so the handler honestly sends `unknown` rather than guessing a value. A future contract
revision may pass the persisted incident severity without expanding the payload beyond this
bounded triage summary.

### Two-signal execution gate and audit

Real delivery requires both a non-empty `NOTIFY_WEBHOOK_URL` and
`NOTIFY_REAL_EXECUTION=true` after whitespace trimming and case normalization. Every other
configuration uses the existing no-network simulation path. The URL is the credential signal and
the execution flag is the independent enablement signal.

Successful HTTP 2xx delivery records `integration=webhook`,
`operation=send_webhook_notification`, `mode=real`, and the status code. Simulation records the
same operation with `mode=simulation`. Timeout, connection, and non-2xx outcomes become clean
failed execution snapshots through `ActionExecutionError`; neither the URL nor a response body is
retained.

### Why there is no confirmation read

The confirmation-read pattern used by earlier integrations verifies a separate external state
after requesting infrastructure mutation. A webhook delivery has no such state: acceptance of the
HTTP request is the entire operation, and generic webhook targets expose no portable read API for
the delivered message. Success is therefore based only on the HTTP 2xx response. Inventing a
second request would neither confirm human receipt nor improve correctness.

## Consequences

With both variables absent, the demo behaves exactly as before and makes no webhook request. A
configured real delivery can notify an external administrator channel without changing security
infrastructure. Operators must store and rotate the URL like an API token, restrict who can read
the process environment, limit outbound access to the intended webhook host, and monitor delivery
failures without logging request URLs or bodies.

HTTP success confirms endpoint acceptance, not that an administrator read or acted on the
message. Retries are deliberately absent because an unkeyed retry could create duplicate alerts;
durable delivery and idempotency policy remain future work.
