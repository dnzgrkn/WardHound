WardHound turns disconnected NAC, PAM, and identity signals into a single explainable incident, scores it deterministically, explains it with a constrained AI analysis layer, and routes any remediation through a human-approval-gated workflow. Since v0.3.0, JumpServer and PacketFence evidence collection moved from operator-run bridge scripts to continuously scheduled, PAM-audited transports, the daily digest became fully automatic with PDF export and gated delivery, and Active Directory's equivalent continuous transport was built and safely gated — implemented, but explicitly not yet confirmed end-to-end against a live domain controller.

## Highlights since v0.3.0

- **Continuous JumpServer polling** (ADR 0022): a Celery worker and beat scheduler now poll JumpServer's session/login-log history every 300 seconds by default through the existing AccessKey/HMAC client. A Redis-backed UTC watermark makes repeated polling idempotent; a failed cycle retries the same window instead of silently losing activity. The task makes zero network calls unless its configuration signals are all present.
- **Continuous PacketFence polling through JumpServer's audited Ops Job API** (ADR 0024): rather than adding a direct PacketFence credential, WardHound runs `pfcmd node view category="Quarantine"` as an ad-hoc job brokered by JumpServer, so the command stays inside JumpServer's own PAM session/command audit trail. A Redis quarantine-snapshot diff makes polling idempotent and correctly re-alerts a device that leaves and later re-enters quarantine.
- **Active Directory continuous polling — implemented, live validation pending** (ADR 0025): the same audited Ops Job mechanism was adapted for AD, reusing the Event ID 4625 `Get-WinEvent`/XML extraction already validated in ADR 0021 and gated the same five-signal way as the other two transports. After adding a WinRM protocol entry to the domain-controller asset, `win_shell` passed JumpServer's module-compatibility check, but no successful end-to-end output was observed against the live domain controller before lab access ended — the suspected cause is a pending cross-VLAN WinRM firewall rule. This is stated plainly in the ADR rather than represented as proven.
- **Daily Security Digest is now fully automatic** (ADR 0023): scheduled generation (every 24 hours by default) degrades gracefully to a narrative-free report if the AI provider is unavailable or fails; a new PDF export endpoint renders any retained digest with `reportlab`; and an optional, safety-gated Slack-compatible webhook delivery requires both a destination URL and an explicit real-execution flag, and only ever sends bounded counts and a capped summary — never raw evidence.
- **265 automated tests pass** (1 skipped without a locally running PostgreSQL instance), `ruff` + `mypy` clean, including new coverage for watermark idempotency and boundary handling on all three collector transports, quarantine snapshot re-alerting, the zero-config gate on each scheduled task, PDF rendering, and gated webhook delivery.

## What's real

- **Collectors** (PacketFence, JumpServer, Active Directory): parsing/normalization verified against real source formats, with the full ingestion→correlation→incident pipeline previously run against three real, concurrently live systems producing a genuine incident (ADR 0021, see [case study](docs/CASE_STUDY.md)). JumpServer and PacketFence are now continuously scheduled through audited transports (ADR 0022, ADR 0024); Active Directory's equivalent transport is implemented and gated identically but not yet confirmed against a live domain controller (ADR 0025).
- **Daily Security Digest**: deterministic activity aggregation over a configurable window, optional typed AI narrative, Postgres-backed history, automatic scheduled generation, PDF export, and safety-gated webhook delivery
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
- JumpServer and PacketFence continuous collector transports are proven end-to-end against real infrastructure; Active Directory's continuous transport is implemented and gated the same safe way, but the last live attempts timed out and the transport remains unconfirmed pending a network ACL change outside this project's control (ADR 0025) — a materially weaker claim than the other two, stated as such rather than glossed over
- A push-based syslog listener for sources that cannot be polled remains future work
- No ML-based anomaly detection and no multi-tenant isolation — both deliberately deferred, see below

See [README](README.md) for the full architecture diagram and setup instructions, [THREAT_MODEL.md](docs/THREAT_MODEL.md) for this platform's own attack surface, and `docs/adr/0011` through `docs/adr/0025` for the design record of every real integration and validation stage since.

## What's next

See the "v2 / Sonraki adımlar" section of [ROADMAP.md](docs/ROADMAP.md). ML-based anomaly detection needs a volume of real historical data and an evaluation framework that don't exist yet; multi-tenant isolation has no real second tenant to design against. Active Directory's continuous transport needs one authorized live poll cycle, once the pending cross-VLAN WinRM ACL is in place, to move from "implemented, unconfirmed" to validated. Building the deferred v2 items now would be premature, not a missing feature.
