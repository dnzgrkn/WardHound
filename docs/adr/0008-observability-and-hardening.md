# ADR 0008: Observability and Test Hardening

## Status
Accepted

## Context
WardHound's deterministic engines and dashboard API need enough production signals to diagnose
failures and audit security-action transitions without copying confidential source-system payloads
into secondary stores. The core engines also need an enforceable coverage floor, and the local
Compose demonstration must make metrics and traces viewable rather than merely emit them.

## Decision
Use Python standard-library logging with a small JSON formatter. Authentication rejection, API
errors, AI analysis failure, and every response-action lifecycle transition are logged with UUIDs,
bounded enum values, and statuses. Attempted keys, operator identifiers, full events, raw payloads,
and `extra_attributes` are excluded. This avoids an additional logging dependency while producing
machine-readable records.

Use `prometheus-client` directly for a deliberately small metric set: HTTP request count and
latency by route/method/status; newly retained incidents by severity; response transitions by
action type; and AI analysis outcomes and latency. These labels are finite enums or route
templates, preventing user-controlled high-cardinality series. Prometheus scrapes `/metrics`, and
a provisioned Grafana dashboard shows incident rate, action transitions, AI success and p95
latency, and API p95 latency.

Use OpenTelemetry FastAPI instrumentation for inbound HTTP spans and explicit spans around event
pipeline execution and the external AI analysis call. Explicit attributes contain incident UUIDs,
counts, and event types, never event bodies or entity values. The OTLP HTTP endpoint is configured
by `OTEL_EXPORTER_OTLP_ENDPOINT`; local Compose exports to Jaeger's all-in-one service and exposes
its UI.

CI measures `app.engines` on the complete pytest suite and fails below 90 percent statement
coverage. The threshold targets the independent business engines rather than forcing API,
collector, and integration code into the same testability model. Edge-case tests focus on window
boundaries, combined policy behavior, bounded risk scoring, and defensive response gating.

All secret-shaped configuration flows through environment variables and the gitignored `.env`.
Compose requires database, API, broker, and Grafana credentials instead of embedding usable
fallbacks. Docker secrets are deferred for the single-host, single-operator demo: adopting them now
would add dual configuration paths without protecting against host compromise. A production
multi-host deployment should use an orchestrator or managed secret store with scoped identities,
rotation, and auditability rather than treating `.env` as production secret management.

## Consequences
Operators get correlated logs, bounded metrics, trace visualization, and a portfolio-ready default
dashboard with modest implementation surface. Telemetry intentionally sacrifices raw diagnostic
content to reduce confidentiality risk; investigation requiring event detail stays in the
authorized incident store. Local startup now requires explicit secret values. Jaeger, Prometheus,
and Grafana add memory and disk overhead, and production deployments must authenticate and isolate
those services.
