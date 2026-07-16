# ADR 0021: Real collector evidence ingestion via standalone bridge scripts

- Status: Accepted
- Date: 2026-07-16

## Context

ADR 0003 confirmed that the PacketFence, JumpServer, and Active Directory collectors' `parse_raw()`/
`normalize()` logic matches the real event shapes those systems emit. That validated format
compatibility offline; it did not prove that a collector's output, sent through WardHound's own
running instance, produces a genuine correlated incident. Every incident anyone had seen up to this
point — in the demo and in every collector test — was either fully synthetic or a single normalized
event asserted against in isolation. `CrossSystemCompromiseRule` (ADR 0004) requires simultaneous
AD, PacketFence, and JumpServer evidence for the same entity within a fixed window; nothing had
exercised that rule against three independently live systems at once.

WardHound's continuous collector transports — the PacketFence syslog listener, the JumpServer
polling scheduler, AD WinRM/WEF forwarding — are deliberately out of scope until a later stage (the
README states this plainly: "Collector transports are not continuously scheduled"). Building that
scheduling infrastructure was not required to answer the narrower question this stage needed
answered while lab access was available: does the already-reviewed collector logic actually produce
a real cross-system incident against live infrastructure, not just parse a sample correctly?

The live lab environment's real API responses differed from what ADR 0003's format check and the
collectors' existing unit tests assumed in several concrete ways: JumpServer's `sessions` and
`login-logs` REST endpoints return bare JSON arrays rather than the paginated `{"results": [...],
"next": ...}` envelope `JumpServerCollector._fetch_records()` requires; JumpServer session
`date_start`/`date_end` use the same non-ISO `"%Y/%m/%d %H:%M:%S %z"` format as login timestamps,
not ISO 8601; and JumpServer's `sessions` endpoint's `user` field is `"Display Name(username)"`
(e.g. `"Administrator(admin)"`) where its `login-logs` endpoint's equivalent field is a bare
username for the same account. That last one is not a parsing failure — it parses fine — but it
silently breaks `CrossSystemCompromiseRule`'s username-based entity matching, since the rule
requires an exact casefolded string match across sources and neither collector nor correlation
engine raises any error when a match simply fails to occur.

## Decision

### Standalone bridge scripts, not modified collectors

Four scripts under `scripts/` (`ingest_jumpserver_live.py`, `ingest_ad_events.py`,
`ingest_packetfence_live.py`, `export-ad-security-events.ps1`) pull real activity from a live lab
environment and POST normalized events through the existing, unmodified `/api/v1/events` endpoint.
Each script reuses the real collector's `parse_raw()`/`normalize()`/`process()` unchanged and adapts
only the response-shape mismatches above — pagination tolerance, datetime reformatting, and username
extraction — entirely within the bridge script, before handing records to the reviewed collector
code. `app/collectors/*.py` were read in full and never edited. This keeps the already-reviewed,
tested parsing logic authoritative and isolates every real-world quirk found during this validation
to code that is explicitly a one-shot operator tool, not part of the deployed service.

### AccessKey signing instead of weakening JumpServer's MFA policy

This JumpServer instance enforces MFA org-wide on every interactive login
(`POST /api/v1/authentication/auth/`), with no per-account exception, which blocks a plain
username/password script login. Rather than disabling or narrowing that policy to unblock
automation, `ingest_jumpserver_live.py` uses JumpServer's own documented AccessKey mechanism: an
ID/Secret pair signs each request with HMAC-SHA256 over `(request-target)`, `accept`, `date`, and
`host` (the "Signing HTTP Messages" scheme JumpServer's `drf-httpsig` backend implements), bypassing
the interactive login/MFA flow entirely because the request never goes through it. This is the
mechanism JumpServer documents for headless automation against an MFA-enforced tenant, not a
workaround — the org's MFA policy is unchanged and no account's protection is weakened. The
credential used (`wardhound-reader`) was created with a read-only System Auditor role and no group
memberships, since group membership controls asset/session access on this platform, not audit-log
read.

### PacketFence evidence read via `pfcmd`, not the write-path REST API

WardHound already has a real, safety-gated PacketFence write integration (ADR 0011,
`PUT /api/v1/node/{mac}/apply_security_event`). That path assumes a reachable REST API with
configured webservices credentials or an API client. This lab's PacketFence instance has neither —
`[webservices].user` is unset and no security-event classes are configured — and the instance itself
is reachable only through a JumpServer-proxied asset session, not directly from the machine running
WardHound. Rather than provisioning REST access purely for this validation, `ingest_packetfence_live.py`
takes a small JSON record (MAC, `pid`, category, status) that an operator produces from a real shell
on the PacketFence box via `pfcmd node view` — the same CLI PacketFence's own administrators use —
and turns it into a `DEVICE_QUARANTINED` event through the unmodified collector. Quarantine itself
was triggered as a genuine PacketFence state change (a real `node_category` assignment via SQL insert
+ `pfcmd node edit`), not fabricated event data layered on top of an unchanged system.

`PacketFenceCollector._build_device_event()` does not attach a related username to
`DEVICE_QUARANTINED` events, because its REST polling path (`poll_node_status()`) has no such field
to draw from. `pfcmd node view`'s own output does carry that link (`pid`), so the bridge script
enriches the resulting event with a `related_entities` username via `model_copy()` — the same
technique `PacketFenceCollector._normalize_vlan()` already uses internally for its own username
enrichment. This is real evidence PacketFence already holds, surfaced through a script rather than a
collector code change, not an invented fact.

### Cross-system correlation is exact-string and fails silently

`CrossSystemCompromiseRule._entity_keys()` matches on casefolded username or normalized MAC address
with no fuzzy matching. The JumpServer session `user` field quirk above meant a structurally valid,
correctly parsed `SESSION_STARTED` event simply never joined the correlation cluster its AD and
PacketFence counterparts were in — no exception, no log line, just zero incidents where one was
expected. This is worth recording as an operational risk independent of this validation: any future
collector or bridge integration that produces a technically valid `NormalizedEvent` with a
subtly-wrong entity string will silently prevent correlation rather than erroring, and is only
detectable by inspecting the actual entity values on stored events.

## Consequences

The full pipeline — real collector parsing, real HTTP ingestion, deterministic cross-system
correlation, real risk scoring — has now been exercised against three simultaneously live systems
and produced one genuine, explainable, evidence-linked `critical` incident (risk 100), not a
synthetic or single-system result. That is a materially stronger validation claim than ADR 0003's
offline format check.

The bridge scripts are deliberately kept outside `app/`: they are operator-run, one-shot tools with
no scheduling, no test suite, and no production entry point, matching their actual purpose (a
validation instrument for a time-limited lab access window, not a new product surface). They accept
all lab-specific values — base URLs, credentials, device/user identifiers — as environment variables
or JSON input; no real internship hostname, IP beyond RFC1918 examples, username, or secret is
hardcoded in committed script text, consistent with this project's confidentiality rule.

Repeated runs against the same real lab state are not idempotent: `NormalizedEvent.id` is randomly
generated per `collector.process()` call, so re-ingesting the same underlying real activity (as
happened repeatedly during interactive testing) produces distinct event sets and can create
duplicate incidents with identical evidence. This is expected and harmless for validation but would
need addressing (e.g. deterministic IDs derived from source record identity) before any of these
scripts were adapted into a continuously-scheduled collector transport.

Continuous collector scheduling (the syslog listener, the JumpServer poll loop, AD WEF/WinRM) remains
future work, as already stated in the README and roadmap. This stage deliberately did not build that
infrastructure — it proved the pipeline downstream of ingestion is correct against real data, which
is the harder and more valuable thing to get right before investing in always-on transports.
