WardHound turns disconnected NAC, PAM, and identity signals into a single explainable incident, scores it deterministically, explains it with a constrained AI analysis layer, and routes any remediation through a human-approval-gated workflow — with five response actions now able to execute for real against live infrastructure, still never autonomously.

## Highlights since v0.1.0

- **Persistent data layer**: events, incidents, analyses, and approvals now survive an API restart (PostgreSQL + SQLAlchemy async + Alembic), with store protocols fully async end to end and a concurrency test proving overlapping requests don't serialize.
- **Real identity**: the static demo API key still covers read/demo paths, but requesting, approving, or rejecting a response action now requires a genuine Auth0 Bearer token with the right permission — the approving identity comes from the verified token, not client input.
- **Five real SOAR integrations**, each gated behind multiple independent configuration signals plus mandatory human approval, and each verifying the actual resulting state rather than trusting a bare "accepted" response before reporting success:
  - PacketFence device quarantine (security-event-driven isolation)
  - Active Directory account disablement (LDAPS, confirmed via a `userAccountControl` re-read)
  - Cisco Secure Firewall (FMC) dynamic IP blocklist membership
  - JumpServer privileged session termination
  - Duo Security step-up verification challenge
- **Two low-risk real integrations**: administrator webhook notifications and external ticket creation, both vendor-agnostic and tested for zero credential/raw-event leakage into outgoing payloads.
- **One accuracy fix, not a new integration**: the manual-approval handler now reports the real approving identity and timestamp instead of stale hypothetical-future-tense language, since that checkpoint was already genuinely satisfied by the time it runs.
- **Secrets-provider seam**: every real-execution handler now reads its configuration through a small async interface rather than inline `os.getenv` — zero behavior change today, ready for a future remote secrets backend without another cross-cutting rewrite.
- **All 222 automated tests pass**, `ruff` + `mypy` clean.

Three real defects were found and fixed during this work — all after the implementing agent's own test suite had already passed, caught only by independently reading the real target system's source or documentation before merging:

- A correlation combinatorial explosion (one repeated evidence chain produced N×M×K duplicate incidents instead of one).
- An event-loop-blocking persistence shim (synchronous store protocols hidden behind a thread-and-nested-event-loop wrapper, serializing the API under concurrent load).
- A wrong PacketFence endpoint (`bulk_deregister`, which removes a device's registration, used where `apply_security_event`, which actually drives isolation, was required).

## What's real

- **Collectors** (PacketFence, JumpServer, Active Directory): parsing/normalization verified against real source formats from a live enterprise Zero Trust engagement (fully anonymized, see [case study](docs/CASE_STUDY.md))
- **Correlation, policy, and risk engines**: deterministic, rule-based, independently tested, with entity+time-window clustering so repeated matching evidence consolidates into one incident instead of a combinatorial explosion
- **AI analysis** (Claude + Instructor): on-demand, typed structured output only, cites retained evidence, cannot execute anything
- **Response engine**: typed action models, mandatory human approval before any privileged action, full audit trail, five of eight actions capable of real execution when explicitly configured
- **Real identity**: Auth0-federated authorization for requesting/approving/rejecting response actions, with a separated analyst/approver permission model
- **Persistent data layer**: PostgreSQL-backed stores for events, incidents, analyses, and response approvals — incident state survives an API restart
- **Dashboard**: React + WebSocket realtime, incident triage, evidence timeline, approve/reject workflow
- **Observability**: Prometheus metrics, Grafana dashboard, OpenTelemetry tracing (Jaeger), structured JSON logging
- **222 automated tests**, `ruff` + `mypy` clean

## What's simulated / not yet real

- All eight response actions are **simulated by default** and only become real when their specific configuration signals are explicitly set (multiple independent environment variables plus a real-execution flag) — zero configuration means zero network calls, matching today's demo behavior exactly
- Seven of eight actions follow this real-when-configured pattern: quarantine (PacketFence), disable user (Active Directory), block IP (Cisco FMC), close session (JumpServer), require MFA (Duo), notify administrator (webhook), create incident (ticketing webhook)
- The eighth, require-manual-approval, is not an external integration — it now always reports the real approving identity, since that checkpoint has already genuinely happened by the time it runs
- No response action ever executes without human approval, regardless of configuration
- Collectors are parsing logic, not continuously running ingestion services
- No ML-based anomaly detection and no multi-tenant isolation — both deliberately deferred, see below

See [README](README.md) for the full architecture diagram and setup instructions, [THREAT_MODEL.md](docs/THREAT_MODEL.md) for this platform's own attack surface, and `docs/adr/0011` through `docs/adr/0019` for the design record of every real integration.

## What's next

See the "v2 / Sonraki adımlar" section of [ROADMAP.md](docs/ROADMAP.md). Both remaining items are intentionally deferred rather than in progress: ML-based anomaly detection needs a volume of real historical data and an evaluation framework that don't exist yet, and multi-tenant isolation has no real second tenant to design against. Building either now would be premature architecture, not a missing feature.
