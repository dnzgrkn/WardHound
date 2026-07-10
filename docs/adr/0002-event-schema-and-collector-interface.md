# ADR 0002: Event Schema Design and Collector Interface

## Status
Accepted

## Context

WardHound ingests events from four structurally different enterprise source systems:

| Source | Transport | Identity anchor | Event granularity |
|---|---|---|---|
| PacketFence (NAC) | Syslog UDP/TCP | MAC address | Per-device NAC decision |
| JumpServer (PAM) | REST API poll | Username + session ID | Per-session / per-command |
| Active Directory | WinRM / WEF | Username + domain | Per-authentication / directory change |
| Firewall | Syslog UDP/TCP | IP address (may be unresolved) | Per-connection / per-rule |

Every downstream engine — correlation, risk scoring, policy enforcement, AI analysis — needs a single, source-agnostic event contract. The design of `RawEvent`, `NormalizedEvent`, and `BaseCollector` locks in the pipeline's data contract for the entire project lifetime. Getting these wrong is expensive: a schema change requires migrations, replay logic, and updates to every consumer.

Three design decisions required explicit trade-offs:

1. How to model the "entity" that an event is about across heterogeneous identity anchors.
2. Where to draw the boundary between parsing and normalization in the collector pipeline.
3. Whether normalization logic lives on the collector or on a separate normalizer class.

---

## Decision 1: Entity Modeling — Single Flexible Model, Not a Discriminated Union

### Options considered

**Option A — Discriminated union** (`UserEntity | DeviceEntity | IpEntity`): each subtype has only the fields it needs; Pydantic's discriminated union enforces correct field combinations at validation time.

**Option B — Single model with optional identity fields** (`NormalizedEntity` with `username | None`, `mac_address | None`, `ip_address | None`, etc.): one class, enforces "at least one identifier" via `@model_validator`.

**Option C — Dict/free-form** (`entity: dict[str, Any]`): no validation at all, maximum flexibility.

### Decision: Option B

Real-world events from enterprise sources are often *partially identified*:
- A PacketFence authentication failure knows the MAC address but not the username until 802.1X EAP completes. The device IS identified; only the user is unknown.
- A JumpServer session knows the username, the session ID, and the source IP, but the destination hostname might be an IP that requires a reverse DNS lookup WardHound doesn't perform inline.
- An AD failed auth knows the username and domain but doesn't include the source device MAC — only the workstation hostname, if the event log includes it.

A strict discriminated union would force a *choose one type* decision that doesn't reflect reality. Representing these as "a USER entity with an ip_address field also set" is not a type error — it's data that should be preserved.

Option C eliminates all validation, which violates the engineering principle of typed Python everywhere.

Option B with a `model_validator` enforcing at least one identifier gives us:
- A single class all consumers work with (no `isinstance` chains in the correlation engine).
- Flexible population: the collector sets only the fields it can extract.
- A `display_name` property that returns a human-readable label without callers needing to know which field is populated.
- Strict enough validation to catch bugs (empty entity: rejected at ingest time).

### Extensibility

When a new source system is onboarded (e.g., a SIEM that provides a GUID-based identity), add an optional field to `NormalizedEntity` (backward-compatible) and update `display_name`. The downstream engines that use `display_name` need no changes. Engines that use a specific field (e.g., a correlation rule keyed on `mac_address`) remain unaffected.

### What we intentionally gave up

The discriminated union would have given us compile-time proof that "if entity_type is USER, mac_address is never set." We gave that up for model simplicity and to match the messiness of real event data. The `entity_type` field still signals *intent* to callers; it just isn't enforced at the field-presence level.

---

## Decision 2: `NormalizedEventType` as a Shared Semantic Vocabulary

Cross-source correlation (e.g., detecting a password spray that spans NAC + AD) requires that `AUTH_FAILED` from PacketFence and `AUTH_FAILED` from Active Directory are the *same* event type, distinguished only by `source_system`.

If we had source-specific enums (`PacketFenceEventType`, `ADEventType`), the correlation engine would need to enumerate all synonymous pairs. Instead, `NormalizedEventType` is the semantic vocabulary: it represents *what happened*, not which system emitted the signal. The `source_system` field on `NormalizedEvent` answers *where it came from*.

Events that are truly source-system-specific (e.g., `VLAN_ASSIGNED` only happens in PacketFence) still belong in the shared enum — they simply won't appear in events from other sources. This avoids a proliferation of enums.

### Adding a new source system

When adding a new source (e.g., Azure AD / Entra ID):
1. Add `AZURE_AD = "azure_ad"` to `SourceSystem`.
2. Map the new source's events to existing `NormalizedEventType` members where semantically correct (e.g., Azure AD failed auth → `AUTH_FAILED`).
3. Add new `NormalizedEventType` members only for events with no existing semantic equivalent.
4. Write a new `BaseCollector` subclass for the new source.

No changes to the correlation engine, risk engine, or AI analysis layer if the event types already exist in the enum.

---

## Decision 3: Normalization Lives on the Collector, Not a Separate Normalizer Class

### Options considered

**Option A — Normalization on the collector** (`BaseCollector.normalize(raw: RawEvent) -> NormalizedEvent`): each collector owns both parsing and normalization of its source.

**Option B — Separate `BaseNormalizer` class**: collectors produce `RawEvent`s; a separate normalizer class (one per source) maps them to `NormalizedEvent`.

**Option C — Centralized normalization function** dispatching by `source_system`.

### Decision: Option A

Normalization is tightly coupled to the source system's schema. The rules for mapping a PacketFence syslog field `mac` to `NormalizedEntity.mac_address` are not reusable by any other source. A separate `BaseNormalizer` class would add an abstraction layer without reducing coupling — you'd still need one normalizer per source system, and it would always be instantiated alongside its collector.

Option B would make sense if normalization were ever shared across collectors (e.g., multiple collectors all producing the same syslog format). That's not the case for WardHound's four target sources. Premature abstraction.

Option C (dispatch function) would grow into an unmaintainable if/elif chain and cannot be independently tested per source.

Option A gives us:
- One class per source system, independently testable.
- `collector.process(data)` as a single entry point that callers and tests use without knowing the internal step split.
- `parse_raw()` and `normalize()` exposed separately for callers that need to inspect the `RawEvent` before normalization (e.g., raw event storage for audit replay).
- Transport-agnostic: the base class defines no I/O. Real collectors add their own async transport (UDP listener, REST poller) that calls `parse_raw()` + `normalize()` inside their event loop.

### Trade-off acknowledged

If we later need to run the same normalization logic from two different transport layers (e.g., both a syslog listener and a SIEM forwarder for PacketFence), the normalization would need to be extracted. At that point, splitting `normalize()` into a separate injected normalizer becomes the right move. Write the ADR then, not now.

---

## Decision 4: `RawEvent` and `NormalizedEvent` Are Immutable

Both models use `model_config = {"frozen": True}`. This prevents accidental mutation after construction, makes events safe to cache and pass across async contexts without defensive copying, and enables future use of events as dict keys or set members (e.g., deduplication sets in the correlation engine).

---

## Consequences

- `app/schemas/events.py` is the single source of truth for the event contract. All four collectors, the correlation engine, the risk engine, the policy engine, and the AI analysis layer import from here. A breaking change here (removing a field, changing an enum value) requires a migration plan.
- Each real collector (PacketFence, JumpServer, AD, Firewall) inherits `BaseCollector` and implements `parse_raw()` + `normalize()`. Week 2 collectors must conform to this interface exactly.
- The `extra_attributes` dict on `NormalizedEvent` is the intentional escape hatch for source-specific fields the AI engine can use. Correlation rules MUST NOT key on `extra_attributes` — if a field is needed for correlation, it must be promoted to a top-level `NormalizedEvent` field with its own ADR justifying the addition.
- `NormalizedEntity.display_name` is a convenience property for UI rendering and AI prompts. It is not a stable identifier for correlation — use the specific identity fields (`username`, `mac_address`, `ip_address`) in correlation rules.
