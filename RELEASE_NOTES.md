WardHound turns disconnected NAC, PAM, and identity signals into a single explainable incident, scores it deterministically, explains it with a constrained AI analysis layer, and routes any remediation through a human-approval-gated workflow. Since v0.2.0, the full pipeline has also been run end-to-end against three real, independently live systems at once — not just validated offline — and a new daily digest turns the activity underneath incidents into an operator-facing summary.

## Highlights since v0.2.0

- **Real, live cross-system validation**: standalone bridge scripts pulled genuine activity from three real, independently running NAC/PAM/AD systems during a scheduled lab window and submitted it through WardHound's own running instance — not the synthetic demo. The unmodified `CrossSystemCompromiseRule` correlated real AD, PacketFence, and JumpServer evidence for one identity into a `critical`, risk-100 incident with a complete, real evidence chain. Two real API-shape mismatches were found and resolved without touching any previously reviewed collector; see [ADR 0021](docs/adr/0021-real-collector-evidence-ingestion.md).
- **Daily Security Digest**: a new deterministic aggregation engine summarizes the prior 24 hours of activity — top users by failed authentication, top devices by quarantine/unknown-device activity, top users by privileged-command/session-anomaly activity, incident counts by severity, and response-action approval/execution counts — with an optional, typed AI executive narrative on top. Degrades gracefully to `narrative=None` with zero Anthropic key configured, and now returns a typed `502` (not a bare crash) if a configured AI provider call fails mid-generation. Three new endpoints (`POST /api/v1/digests/generate`, `GET /api/v1/digests`, `GET /api/v1/digests/{id}`), Postgres-backed history. See [ADR 0020](docs/adr/0020-daily-security-digest.md).
- **Synthetic demo removed**: the dashboard's one-click "Load demo" button and its synthetic evidence generator are gone now that real ingestion is proven to work. The dashboard starts empty until real events are ingested — via the bridge scripts in `scripts/` against a real lab, or directly through `POST /api/v1/events` (see the OpenAPI docs at `/docs`).
- **230 automated tests pass** (1 skipped without a locally running PostgreSQL instance), `ruff` + `mypy` clean, including new coverage for digest window-boundary correctness, ranking/capping, response-action summarization, AI graceful-degradation, and the typed-502 failure path.

## What's real

- **Collectors** (PacketFence, JumpServer, Active Directory): parsing/normalization verified against real source formats, and — as of this release — the full ingestion→correlation→incident pipeline verified against three real, concurrently live systems producing a genuine incident (fully anonymized, see [case study](docs/CASE_STUDY.md))
- **Daily Security Digest**: deterministic activity aggregation over a configurable window, optional typed AI narrative, Postgres-backed history
- **Correlation, policy, and risk engines**: deterministic, rule-based, independently tested, with entity+time-window clustering so repeated matching evidence consolidates into one incident instead of a combinatorial explosion
- **AI analysis** (Claude + Instructor): on-demand, typed structured output only, cites retained evidence, cannot execute anything
- **Response engine**: typed action models, mandatory human approval before any privileged action, full audit trail, five of eight actions capable of real execution when explicitly configured
- **Real identity**: Auth0-federated authorization for requesting/approving/rejecting response actions, with a separated analyst/approver permission model
- **Persistent data layer**: PostgreSQL-backed stores for events, incidents, analyses, response approvals, and daily digests — state survives an API restart
- **Dashboard**: React + WebSocket realtime, incident triage, evidence timeline, approve/reject workflow — no synthetic-data shortcut
- **Observability**: Prometheus metrics, Grafana dashboard, OpenTelemetry tracing (Jaeger), structured JSON logging

## What's simulated / not yet real

- All eight response actions are **simulated by default** and only become real when their specific configuration signals are explicitly set (multiple independent environment variables plus a real-execution flag) — zero configuration means zero network calls, matching today's demo behavior exactly
- Seven of eight actions follow this real-when-configured pattern: quarantine (PacketFence), disable user (Active Directory), block IP (Cisco FMC), close session (JumpServer), require MFA (Duo), notify administrator (webhook), create incident (ticketing webhook)
- The eighth, require-manual-approval, is not an external integration — it always reports the real approving identity, since that checkpoint has already genuinely happened by the time it runs
- No response action ever executes without human approval, regardless of configuration
- Collectors are parsing/ingestion logic exercised by operator-run bridge scripts, not continuously scheduled ingestion services — the syslog listener, JumpServer poll loop, and AD WEF/WinRM transport remain future work
- No ML-based anomaly detection and no multi-tenant isolation — both deliberately deferred, see below

See [README](README.md) for the full architecture diagram and setup instructions, [THREAT_MODEL.md](docs/THREAT_MODEL.md) for this platform's own attack surface, and `docs/adr/0011` through `docs/adr/0021` for the design record of every real integration and validation stage since.

## What's next

See the "v2 / Sonraki adımlar" section of [ROADMAP.md](docs/ROADMAP.md). ML-based anomaly detection needs a volume of real historical data and an evaluation framework that don't exist yet; multi-tenant isolation has no real second tenant to design against; and continuous collector scheduling was deliberately deferred again this release in favor of proving the pipeline downstream of ingestion is correct first. Building any of these now would be premature, not a missing feature.
