# ADR 0003: Verified collector parsing formats

- Status: Accepted
- Date: 2026-07-10
- Verified: 2026-07-13

## Context

Stage 2 originally used provisional parsing assumptions while representative source data was
unavailable. PacketFence console/SSH logs and JumpServer REST responses plus DRF OPTIONS schemas
have now been checked against deployed systems. The sanitized formats and decisions below replace
those assumptions. Active Directory field names were also checked against XML-rendered Windows
Security events.

## Decision

### PacketFence

PacketFence file output uses an RFC3164-like header, `timestamp hostname tag[pid]: message`, with an
ISO 8601 timestamp. It has no RFC5424 priority/version prefix or structured-data block. Two distinct
log sources are parsed separately.

`radius.log` contains FreeRADIUS authentication results such as:

```text
2026-07-09T15:47:10.550655+03:00 packetfence auth[6092]: (189650)   Login OK: [CORP\jdoe] (from client SW-Access-01 port 65551 cli AA:BB:CC:DD:EE:FF via TLS tunnel)
2026-07-02T17:31:56.619915+03:00 packetfence auth[1953556]: (530) Login incorrect (mschap: synthetic rejection reason): [CORP\jdoe] (from client SW-Access-01 port 65551 cli AA:BB:CC:DD:EE:FF)
```

Whitespace before the result and the `via TLS tunnel` suffix are variable. `Login OK` maps to
`AUTH_SUCCEEDED`; `Login incorrect` maps to `AUTH_FAILED`, with its parenthesized reason retained.
The FreeRADIUS request counter is preserved as context but is not an idempotency key.

For these 802.1X events, the MAC-addressed `DEVICE` remains `primary_entity`, and the resolved
`DOMAIN\username` becomes a related `USER`. PacketFence remains device-centric across auth, VLAN,
and node-state signals, which gives the correlation engine one stable NAC subject even when an
identity is absent in MAC-auth flows. Making the user primary only for 802.1X would fragment that
source-level identity model.

`packetfence.log` emits a two-line `httpd.aaa` sequence for every successful Access-Accept:

```text
2026-07-07T02:23:37.770855+03:00 packetfence httpd.aaa-docker-wrapper[909654]: httpd.aaa(7) INFO: [mac:AA:BB:CC:DD:EE:FF] PID: "jdoe", Status: reg Returned VLAN: (undefined), Role: Accounting (pf::role::fetchRoleForNode)
2026-07-07T02:23:37.775741+03:00 packetfence httpd.aaa-docker-wrapper[909654]: httpd.aaa(7) INFO: [mac:AA:BB:CC:DD:EE:FF] (10.20.30.2) Added VLAN 45 to the returned RADIUS Access-Accept (pf::Switch::Template::returnRadiusAccessAccept)
```

The collector correlates the context and assignment lines by source host, MAC, and a five-second
request window. PacketFence's `PID` field here means Person ID, not operating-system process ID.
Every pair emits `VLAN_ASSIGNED`; deciding whether the VLAN actually changed belongs to Stage 3.
PacketFence node status is only `reg` or `unreg`. Isolation is represented by the role/category,
where the source-system term is *isolated* even though WardHound's enum remains
`DEVICE_QUARANTINED`.

`DEVICE_UNKNOWN`, `DEVICE_REGISTERED`, and `DEVICE_QUARANTINED` are not available as per-device
transitions in PacketFence's default log streams. They therefore use a poll-based sub-collector
against the PacketFence REST node resource, not direct database access. It snapshots state per MAC
and diffs consecutive polls: first observation emits `DEVICE_UNKNOWN`, `unreg` to `reg` emits
`DEVICE_REGISTERED`, and a category change into an isolation/quarantine role emits
`DEVICE_QUARANTINED`. `unregdate` is never interpreted as an event time because it is a scheduled
expiry on registered nodes. The in-memory prior-state cache is appropriate for this Stage 2
collector; durable checkpointing belongs with production collection orchestration.

### JumpServer

JumpServer is polled as three distinct paginated DRF resources. Responses use a
`count`/`next`/`previous`/`results` envelope, and `next` links are followed.

Login logs from `/api/v1/audits/login-logs/` use labeled-choice objects for `type`, `mfa`, and
`status`; their `.value` members are read. Boolean `status.value` maps to `AUTH_SUCCEEDED` or
`AUTH_FAILED`. A successful username such as `Jane Doe(jdoe)` normalizes to `jdoe`, while a bare
failed-login value such as `jdoe` is retained unchanged. Login time uses the explicit
`YYYY/MM/DD HH:MM:SS ±ZZZZ` format. Failure reasons and the authentication backend are preserved.

Sessions from `/api/v1/terminal/sessions/` keep the JumpServer user, target account, and target
asset separate. The user is primary, the asset is related, and account identifiers remain source
context. `date_start` and `date_end` are ISO 8601. The poller remembers `is_finished` by session ID:
a newly observed open session emits `SESSION_STARTED`, and only a later `false` to `true` transition
emits `SESSION_ENDED`. An already-finished session first seen after collection begins emits neither,
because its start/end transition was not observed.

Commands from `/api/v1/terminal/commands/` parse integer `timestamp` values as Unix epochs. The
base64 `output` is retained verbatim in `extra_attributes`; decoding could introduce arbitrary
binary or unbounded terminal output into normalized text. `session`, `account`, `input`, and remote
address are retained for investigation.

Command-filter `risk_level.value` maps as follows:

| Value | Verdict | Event type | Severity |
| --- | --- | --- | --- |
| 0 | Accept | `PRIVILEGED_COMMAND_EXECUTED` | `LOW` |
| 7 | Review & Accept | `PRIVILEGED_COMMAND_EXECUTED` | `MEDIUM` |
| 4 | Warning | `PRIVILEGED_COMMAND_EXECUTED` | `HIGH` |
| 8 | Review & Cancel | `PRIVILEGED_COMMAND_EXECUTED` | `HIGH` |
| 5 | Reject | `SESSION_ANOMALY_DETECTED` | `HIGH` |
| 6 | Review & Reject | `SESSION_ANOMALY_DETECTED` | `CRITICAL` |

Reject verdicts are anomalies because the policy engine affirmatively blocked the command. Warning
and cancel verdicts remain command events because they do not mean that an anomalous command
executed: warning allows execution, while cancellation is a reviewed workflow outcome. Their high
severity still makes them visible for correlation. Human-reviewed acceptance is medium rather than
low because it indicates a policy-sensitive command that required approval.

Each polling resource formats its lower-bound filter according to its own representation: login
logs use JumpServer's slash-formatted local datetime, sessions use UTC ISO 8601, and commands use a
Unix epoch. A single shared ISO `since` string is not used.

### Active Directory

Windows Security events are converted from event XML into dictionaries. `EventID` and `Computer`
(or `source_host`) are required. `TimeCreated` is an ISO 8601 timestamp. Events 4625 and 4740
identify the account with `TargetUserName`; event 4728 uses `MemberName`. `TargetDomainName`
supplies the optional domain. Event-specific context may use `IpAddress`, `CallerComputerName`, and
`GroupName`.

The future transport must call `.ToXml()` before extracting named fields. Raw Windows Event Log
`.Properties` are positional and `Format-List` output does not provide the XML field-name contract
used by this collector.

## Consequences

The parsers reject malformed or unknown source shapes with `ValueError` rather than producing
misleading events. PacketFence collection now combines log ingestion with REST node polling, while
JumpServer polling maintains a small prior-session state cache. Both caches reset when the process
restarts; production persistence and idempotency are collection-orchestration concerns.

Password-spray and tier-violation detection remain excluded because they require correlation across
multiple events and belong to the Stage 3 correlation engine.
