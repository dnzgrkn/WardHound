# ADR 0023: Digest scheduling, PDF export, and delivery

- Status: Accepted
- Date: 2026-07-17

## Context

ADR 0020 established a persisted, deterministic `DailyDigest` and explicitly deferred daily
scheduling, PDF export, and delivery. ADR 0022 subsequently wired Celery worker and beat into the
Compose runtime. The remaining work is to generate the trailing 24-hour report without operator
action, make a retained report portable, and optionally notify an external channel without exposing
the evidence WardHound retains.

## Decision

### Daily task and degradation

The existing Celery composition root registers `app.tasks.digest.generate_daily_digest` alongside
the JumpServer task. Its default interval is 86,400 seconds, with
`DIGEST_SCHEDULE_INTERVAL_SECONDS` available for deployment tuning and runtime verification. The
task uses the same `DigestBuilder` dependencies as `POST /api/v1/digests/generate` and constructs
`PostgresEventStore`, `PostgresIncidentStore`, `PostgresApprovalStore`, and `PostgresDigestStore`
over a `NullPool` async engine, matching `app/main.py` outside FastAPI's lifespan. One bounded
`asyncio.run()` invocation owns that async lifecycle, following ADR 0022's Celery reasoning.

Missing Anthropic configuration already produces the deterministic report with `narrative=None`.
If a configured provider or typed validation fails, the scheduled task logs the failure, rebuilds
without a narrative, persists the deterministic digest, and still counts generation as successful.
Daily aggregates are operationally useful independent of prose, and discarding them because an
optional provider failed would make reporting less reliable. The manual endpoint retains ADR 0020's
typed 502 behavior because an operator explicitly requested narrative-capable generation and can
act on the immediate error.

### PDF representation

`reportlab` renders a persisted digest directly into PDF bytes. It is a mature Python library with
pagination, tables, and reusable document primitives and requires no Pango/Cairo operating-system
packages in the application image. WeasyPrint would allow HTML/CSS authoring but adds native layout
dependencies and a larger Docker/runtime surface for a compact operational report. The report
includes its period and generation time, optional narrative sections, aggregate statistics, and a
compact incident table containing only title, severity, risk score, and creation time.

`GET /api/v1/digests/{digest_id}/pdf` uses the same static-key boundary and missing-digest response
as the existing digest detail route. It renders only an already-persisted `DailyDigest`; it does not
recompute facts or invoke AI.

### Safety-gated delivery

ADR 0016 is the precedent for webhook delivery. A real attempt requires both a non-empty
`DIGEST_DELIVERY_WEBHOOK_URL` and `DIGEST_DELIVERY_REAL_EXECUTION=true`; either signal alone means
no HTTP client and no network call. Digest generation and persistence are unconditional internal
work, so an absent gate skips only delivery. A delivery failure is logged after persistence and does
not invalidate the retained report.

The request is Slack-compatible JSON with one bounded `text` field. It contains the digest ID,
period, total incident count, critical/high counts, and at most 500 characters of the optional
executive summary. It never receives raw events, evidence chains, entities, credentials, or the
webhook URL. PDF bytes are not attached because generic incoming webhooks accept JSON rather than
portable binary attachments. When `WARDHOUND_PUBLIC_API_URL` is configured, the message links to
the authenticated PDF endpoint; otherwise it names the digest ID and tells the recipient that the
PDF is available through the authenticated API. The API key is never embedded in either reference.

## Consequences

WardHound now retains one automatic trailing-day digest per schedule tick even with no Anthropic
key and no delivery configuration. Operators can retrieve a stable PDF representation of any
retained digest. Enabling delivery adds a small, bounded notification rather than exporting the
underlying security evidence; recipients still need authorized API access to fetch the report.

The interval schedule is elapsed-time based rather than tied to a local midnight. Deployments that
require a calendar or timezone-specific boundary can replace the interval with a Celery crontab
without changing task behavior. Delivery has no automatic retry because the webhook has no portable
idempotency key; durable retry policy remains separate work.
