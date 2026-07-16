# Anonymized validation case study

## Context

WardHound was developed with access to event data from a mid-sized enterprise Zero Trust deployment at Company X. The environment used PacketFence for NAC, JumpServer for privileged access, and Active Directory Tiering for identity boundaries. Representative source formats were checked against real events locally; all committed examples, fixtures, and identifiers are synthetic or anonymized.

This validation established that WardHound's parsers recognize the structures and semantics emitted by those systems. It does not mean that the current repository continuously ingests production traffic: the syslog listener, polling scheduler, and WinRM/WEF transport are not wired as running services.

A later validation pass went further than format-checking: standalone, operator-run scripts pulled real activity from the same three live systems during a scheduled access window and submitted it through WardHound's own running instance, exercising the full deterministic pipeline — not just parsing — against genuinely concurrent, independent evidence sources. Scenario 3 below describes that run. As with Scenario 1 and 2, no real hostname, IP beyond RFC1918 examples, username, or credential from that environment appears here or anywhere in this repository.

## Scenario 1: one identity across NAC, AD, and PAM

Within eight minutes, three controls report signals that are weak or ambiguous in isolation:

1. Active Directory records a failed authentication for `CORP\jdoe` from `WKSTN-0042` (`10.20.30.40`).
2. PacketFence places device `AA:BB:CC:DD:EE:FF` in an isolation role.
3. JumpServer records a new privileged session for `CORP\jdoe`, originating from the same workstation and targeting synthetic Tier 0 host `SRV-T0-0042`.

WardHound normalizes the three source vocabularies and matches the shared username inside the correlation window. The deterministic pipeline creates one incident, attaches any configured policy violations, and calculates a reproducible risk score from the event types, severities, evidence count, and policy bonus. An operator can see exactly which event IDs caused the result; the LLM does not decide whether the incident exists.

If the operator explicitly requests AI analysis, the structured analysis engine receives only bounded normalized evidence. Its result must identify a probable cause, confidence, cited evidence IDs, typed recommended actions, and side effects. A recommendation such as quarantining `AA:BB:CC:DD:EE:FF` enters the approval workflow. Approval produces a simulated audit result describing the call a PacketFence adapter could make; it does not contact PacketFence or change the device.

## Scenario 2: privileged-access boundary violation

JumpServer reports a session by `CORP\jdoe` to `SRV-T0-0042`, but its source is `WKSTN-0042` rather than an operator-configured privileged access workstation. A following command-policy event marks a sensitive command as rejected.

The policy engine can identify the non-PAW access to a configured Tier 0 target, while the PAM anomaly provides direct investigation context. The AI layer may explain the combined evidence and recommend closing the session or disabling the user, but both actions remain typed, human-approved simulations. The operator-supplied approver label is retained in the audit history; it is not a verified user identity under the current shared-API-key authentication model.

## Scenario 3: full pipeline run against three live, concurrent systems

Unlike Scenario 1 and 2, which illustrate the correlation model with representative data, this run
used real, independently observed activity from Company X's live AD, PacketFence, and JumpServer
systems, submitted through WardHound's own running instance rather than asserted against the engine
directly.

One identity failed Active Directory authentication twice within a minute. Within the same short
window, that identity's device was placed into a real PacketFence isolation role — a genuine node
state change on the live system, not a simulated one — and the same identity opened a real,
interactively authenticated JumpServer session to a lab asset. Three independent systems, three
different collectors, no coordination between them beyond the shared entity identity.

WardHound's unmodified `CrossSystemCompromiseRule` correlated the three events inside its configured
window and produced one `critical` incident at the maximum deterministic risk score, with a complete,
timestamped evidence chain attributable back to each source system. No event, entity, or timestamp
in the resulting incident was authored or adjusted for the demonstration; every field came from the
collectors' real `normalize()` output.

Two real-world integration issues surfaced during this run and were resolved without modifying any
previously reviewed collector: one system's session-activity endpoint formatted a user identity
field differently than its authentication-log endpoint for the same account, which silently
prevented username-based correlation until corrected in a thin adaptation layer; and the isolation
signal required reading a live system's own administrative state directly, since REST credentials
for that read path were not provisioned in this environment. Full technical detail, including why
each fix belongs outside the reviewed collectors rather than inside them, is in
`docs/adr/0021-real-collector-evidence-ingestion.md`.

## What the validation demonstrates

- PacketFence, JumpServer, and AD parsing assumptions were checked against real source formats without committing production data.
- The full pipeline — real collector output, real HTTP ingestion, deterministic correlation, reproducible risk scoring — was run end-to-end against three independently live systems at once, not just validated offline or asserted against in isolation (Scenario 3).
- Cross-system signals can be represented by one immutable event contract and evaluated by explainable rules.
- AI analysis is downstream of deterministic detection and constrained to supplied evidence and a closed action vocabulary.
- Privileged responses cannot auto-execute, and the current handlers have no production integration clients.

The case study demonstrates format compatibility and an end-to-end investigation model, including one real, live-system pipeline run, not production readiness. Durable storage, continuous ingestion, per-user authorization, and real response adapters remain future work.
