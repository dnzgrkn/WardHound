# ADR 0004: Correlation, policy, and risk engine design

- Status: Accepted
- Date: 2026-07-13

## Context

Stage 3 needs to turn normalized NAC, PAM, and directory events into explainable incident
candidates. There is not yet an event repository or policy database, and the normalized schema has
no authoritative user-to-device relationship table. The first implementation must therefore keep
its reasoning deterministic, visible, and independently testable against in-memory event
collections.

ADR 0001 requires recording significant trade-offs and the roadmap deliberately starts with
rule-based correlation rather than machine learning. The available validated examples are not a
large, labeled training set, and security operators must be able to explain why an incident was
created and how its risk was calculated.

## Decision

### Engine architecture

`app/engines/` contains three independent modules:

1. The correlation engine runs a registry of small concrete rule objects over normalized events and
   returns incidents.
2. The policy engine runs a separate registry of policy rules over normalized events with explicit
   operator configuration and returns attachable policy violations.
3. The risk engine scores an event collection plus optional violations using readable weight maps.

The thin pipeline composes these in that order. It uses incident event IDs to recover evidence from
the input collection, evaluates policy rules on that evidence, then attaches the score, risk band,
and violations to a copied frozen incident. None of the modules accepts a database session or does
I/O. A future event repository can supply the same `Iterable[NormalizedEvent]` boundary without
changing the engine internals.

Incidents reference normalized event IDs rather than embedding full events. This keeps the
aggregate compact and avoids duplicating immutable event evidence. Incident IDs are derived from
the correlation rule and sorted evidence IDs, making repeated evaluation of the same event set
idempotent. Incident status is present for the later dashboard workflow, but Stage 3 implements no
status transitions.

### Entity matching

A correlation key is extracted from the primary and related entities of each event. Case-insensitive
username equality is the strongest supported cross-system key. This allows AD users, JumpServer
users, and PacketFence 802.1X related users to meet on the same key. When every candidate event has
a username, those usernames must intersect; a shared MAC cannot override conflicting resolved
identities. If at least one event has no username, normalized MAC-address equality is the secondary
key for device-centric chains. Hostname and IP equality are not used for correlation because they
are more likely to be reused, translated, or to represent a target rather than an actor.

The initial rule requires, for one shared key within a configurable 15-minute default window:

- Active Directory `AUTH_FAILED`;
- PacketFence `DEVICE_QUARANTINED`; and
- JumpServer `SESSION_STARTED`.

This strategy intentionally does not infer a user-to-device edge. A PacketFence quarantine event
that has only a MAC cannot correlate with user-only AD and JumpServer events. Usernames are also
matched without requiring a domain because some sources omit it; identical login IDs in two
different domains can therefore collide. Both limitations require a future identity/asset graph or
operator-managed join table, not heuristic matching hidden inside a correlation rule.

Rules implement a small protocol and are held in a registry. Adding another rule requires a new
rule object, not changes to the engine loop. A generic rule language is deferred because the small
verified rule set does not justify a parser or DSL.

### Policy configuration and evaluation

Policies run directly against normalized events. An event is the most precise evidence for a
violation, while incidents are only one possible grouping of those events. The orchestration layer
evaluates the evidence of each correlated incident so findings can be attached without coupling the
policy engine to the incident model.

`PolicyConfig` contains three case-insensitive sets of operator-supplied identifiers:

- `tier_zero_assets`: protected target host/device identifiers;
- `paw_devices`: approved privileged-access workstation host or IP identifiers; and
- `isolated_devices`: MAC, hostname, or IP identifiers whose PacketFence state requires isolation.

The Tier 0 policy examines `SESSION_STARTED`, takes target devices from related entities, and uses
`source_device` or the collector's `remote_addr` context as the access origin. It reports a
violation only when the target is configured as Tier 0, a source identifier is present, and that
source is absent from the PAW set. Missing source context produces no finding because treating
unknown as definitively non-PAW would create misleading evidence.

The quarantine-bypass policy reports a violation when a configured isolated device produces a
PacketFence `AUTH_SUCCEEDED` or `VLAN_ASSIGNED` event. The isolated-device set represents the
operator's current authoritative policy context; the policy engine does not maintain a second NAC
state machine.

Static configuration is the correct Stage 3 boundary because no policy repository, asset inventory,
or lifecycle API exists yet. The explicit configuration object is replaceable later and prevents
synthetic environment identifiers from being hardcoded in rule logic.

### Risk scoring

Risk is deterministic and additive:

```text
score = min(100,
    sum(event_type_weight + severity_weight for each event)
    + 4 * (correlated_event_count - 1)
    + 15 if any policy violation else 0
)
```

Severity contributes independently so an upstream collector can raise the importance of the same
event type. Additional correlated evidence adds a small bonus without overwhelming the semantic
event weights. A policy violation adds one fixed bonus: it is a meaningful escalation, while the
number of rules that happen to describe the same evidence should not multiply risk indefinitely.

Event weights are:

| Event type | Weight | Rationale |
| --- | ---: | --- |
| `AUTH_FAILED` | 8 | Common alone, meaningful in a chain |
| `AUTH_SUCCEEDED` | 2 | Routine without contrary policy context |
| `ACCOUNT_LOCKED_OUT` | 20 | Concrete identity disruption |
| `DEVICE_UNKNOWN` | 8 | Requires review but may be ordinary onboarding |
| `DEVICE_REGISTERED` | 2 | Routine lifecycle event |
| `DEVICE_QUARANTINED` | 24 | NAC made a strong containment decision |
| `VLAN_ASSIGNED` | 5 | Routine unless inconsistent with policy |
| `SESSION_STARTED` | 12 | Opens privileged access exposure |
| `SESSION_ENDED` | 3 | Mostly lifecycle context |
| `PRIVILEGED_COMMAND_EXECUTED` | 15 | Privileged action with direct impact potential |
| `SESSION_ANOMALY_DETECTED` | 25 | PAM policy identified abnormal activity |
| `PASSWORD_SPRAY_DETECTED` | 24 | Multi-event credential attack signal |
| `GROUP_MEMBERSHIP_CHANGED` | 18 | May change effective privilege |
| `TIER_VIOLATION_DETECTED` | 25 | Strong privileged-boundary violation |
| `TRAFFIC_BLOCKED` | 8 | Control succeeded; common without context |
| `LATERAL_MOVEMENT_ATTEMPT` | 25 | Strong compromise-progression signal |
| `PORT_SCAN_DETECTED` | 18 | Reconnaissance signal requiring context |
| `UNEXPECTED_EAST_WEST_TRAFFIC` | 20 | Material internal trust-boundary anomaly |

Severity weights are `LOW=2`, `MEDIUM=6`, `HIGH=12`, and `CRITICAL=20`. Scores map to bands as
`LOW=0–24`, `MEDIUM=25–49`, `HIGH=50–74`, and `CRITICAL=75–100`.

## Consequences

Every incident, violation, and risk score is reproducible and explainable from event evidence plus
configuration. All three engines can be tested or replaced independently. New correlation and
policy behavior is added through concrete rule registries, while scoring changes are data changes
to weight maps.

This design does not retain policy configuration, resolve identities, or fetch event evidence after
the in-memory input collection is released. Those require the future event-store, identity graph,
and policy-management layers and are outside Stage 3.

## Amendment (entity-window clustering)

Correlation matches are clustered per shared entity key instead of taking the Cartesian product of
the rule's requirement buckets. Qualifying events are sorted deterministically by occurrence time
and event ID. Starting with the earliest unconsumed event, the rule gathers every qualifying event
through the inclusive end of the configured window. When that cluster contains at least one event
for every requirement and still satisfies the existing shared-entity rules, it emits one incident
referencing the entire cluster and continues with the next unconsumed event. If a candidate window
is incomplete, the scan advances by one event so later valid evidence is not skipped.

Including all qualifying evidence models repeated submissions inside one temporal cluster as one
ongoing operator-facing situation rather than silently choosing one combination. Consuming a
completed cluster keeps genuinely separate, time-separated sequences distinct. Incident IDs remain
deterministic because they are still UUIDv5 values derived from the rule ID and the sorted IDs of
the evidence included in each cluster.
