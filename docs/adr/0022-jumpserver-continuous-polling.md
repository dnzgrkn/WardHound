# ADR 0022: JumpServer continuous polling

- Status: Accepted
- Date: 2026-07-17

## Context

The Compose worker existed without an application module or registered tasks. ADR 0021 proved that
the reviewed `JumpServerCollector` can produce real evidence, but its operator-run bridge was
one-shot and repeated pulls generated new random event IDs for the same source activity. Continuous
polling therefore needs scheduling, a zero-configuration network gate, and a durable checkpoint.

PacketFence and Active Directory transports remain out of scope. As ADR 0021 records, the available
PacketFence lab has neither syslog forwarding nor REST webservices credentials, while continuous AD
collection requires WinRM/WEF access that is not configured. JumpServer already has a tested
AccessKey/HMAC client suitable for unattended use.

## Decision

### Celery beat and bounded async execution

Celery beat publishes `app.tasks.jumpserver.poll_jumpserver` every 300 seconds by default. Five
minutes is frequent enough for the existing correlation windows without imposing constant audit API
traffic; `JUMPSERVER_POLL_INTERVAL_SECONDS` makes the deployment-specific tradeoff configurable.
Worker and beat load the thin `app.celery_app` composition root, while task behavior lives under
`app/tasks/`.

The Celery task is a synchronous callable, so one invocation uses `asyncio.run()` to own and close
one bounded event loop around its async Redis and HTTP work. This is not ADR 0009's removed shim:
there is no FastAPI request loop or concurrently served API work being blocked, no async store is
wrapped in a worker thread, and no nested loop is created per repository operation. The scheduled
callable itself owns the loop for the duration of one poll-and-ingest cycle.

### Live adaptations and HTTP ingestion

`LiveJumpServerCollector` subclasses the unmodified reviewed collector and overrides only its HTTP
record-fetch boundary. It accepts both bare arrays and paginated envelopes and adapts slash-formatted
session timestamps and display-name usernames before inherited `poll()`, `process()`, and
normalization run. AccessKey signing moved beside that production adapter. The bridge script is now
a thin operator wrapper over the same implementation, so the three ADR 0021 adaptations have one
source of truth.

Normalized batches are sent over HTTP to the running API's real `POST /api/v1/events` endpoint with
`WARDHOUND_API_KEY`. The extra Compose-network hop is small at a five-minute cadence and deliberately
retains API authentication, validation, event persistence, full-history correlation, incident
upsert, metrics, tracing, and realtime broadcasts exactly as an external collector sees them.

### Redis watermark and configuration gate

Redis key `wardhound:collectors:jumpserver:last_successful_poll` stores an ISO 8601 UTC timestamp.
Each cycle captures its cutoff before network work, polls from the stored watermark (or a configurable
300-second initial lookback), discards inclusive API-boundary results at or before that watermark,
and advances to the cutoff only after every event is accepted by the API. An empty result is also a
successful poll. A polling or ingestion failure leaves the old value
unchanged, so the next invocation retries the same window instead of silently losing activity.
Redis is appropriate for this single operational checkpoint because it is already required by
Celery and avoids a schema migration for non-domain state. Loss of Redis state causes only the
bounded initial window to be replayed; PostgreSQL remains authoritative for events and incidents.

Unless `JUMPSERVER_BASE_URL`, `JUMPSERVER_ACCESS_KEY_ID`, and
`JUMPSERVER_ACCESS_KEY_SECRET` are all non-empty, the task logs a skip and returns before creating
Redis or HTTP clients. These AccessKey credentials are independent of `JUMPSERVER_API_TOKEN`, which
continues to gate the ADR 0014 close-session write path.

## Consequences

Compose now runs a registered worker and a separate beat scheduler. Default demo configuration
continues to make zero JumpServer network calls. Deployments that enable polling must retain Redis,
protect both AccessKey fields and the WardHound API key, and size the interval and initial lookback
for their audit volume. Redis is not a permanent event store; a lost checkpoint may replay the
initial window, but failed ingestion never moves the checkpoint forward.
