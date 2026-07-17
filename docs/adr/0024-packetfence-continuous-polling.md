# ADR 0024: PacketFence continuous polling through JumpServer Ops jobs

- Status: Accepted
- Date: 2026-07-17

## Context

ADR 0021 established that this lab's PacketFence instance has no reachable REST/webservices API.
Its real quarantine evidence was available only from `pfcmd` in an operator shell brokered by
JumpServer. Moving that command to continuous polling must not introduce a raw SSH credential that
bypasses the PAM boundary used for the manual proof.

JumpServer's Ops Job API can run an instant ad-hoc shell command against a managed asset and return
the captured Ansible output. The invocation remains inside JumpServer's audit boundary, including
its command logging and session/audit records, while WardHound reuses the AccessKey authentication
already used for continuous JumpServer audit polling. The PacketFence asset name and command account
are identifiers, not PacketFence credentials, and have no defaults.

## Decision

### Audited Ops execution instead of direct SSH

Celery beat publishes `app.tasks.packetfence.poll_packetfence` every 300 seconds by default. Each
bounded synchronous task invocation owns one `asyncio.run()` loop, like ADR 0022. It resolves the
configured asset by exact name, creates an instant shell job, polls task detail to a finite timeout,
then fetches and cleans the execution log. The reusable Ops client accepts the module, arguments,
run-as account, and asset name rather than embedding PacketFence assumptions, so later audited
automation can share the transport.

WardHound runs only `pfcmd node view category="Quarantine"`. ANSI codes, the Ansible result banner,
Celery status trailer, and null padding are removed before the count-and-pipe table is parsed. A
count of zero is a successful empty snapshot. No direct SSH key, PacketFence API token, real asset
name, or real run-as account enters the service or repository.

### Redis quarantine snapshot and retry boundary

Redis set `wardhound:collectors:packetfence:known_quarantine` holds the lowercased MACs in the most
recent successfully processed quarantine snapshot. A cycle subtracts that set from the current
server-filtered result and emits `DEVICE_QUARANTINED` only for new MACs. Events still pass through
the unmodified `PacketFenceCollector.process()` path, and a non-empty `pid` is attached as a related
username entity using the same `model_copy()` technique as the ADR 0021 bridge.

This set difference is simpler than `PacketFenceCollector.poll_node_status()`'s in-memory full
status/category transition tracking because the server-side `category="Quarantine"` filter already
selects the only transition this scheduled rule needs. The Redis set is replaced only after the
event batch is accepted by `/api/v1/events`, or after a successful cycle with no new events. Failed
ingestion leaves the previous snapshot untouched and retries the same new MACs. Replacement also
means a MAC that leaves quarantine disappears from stored state; if it later re-enters, it is new
relative to the last snapshot and correctly alerts again. This is deliberately not an ever-seen set.

The task is gated by five non-empty values: the JumpServer base URL and AccessKey pair plus
`PACKETFENCE_JUMPSERVER_ASSET_NAME` and `PACKETFENCE_JUMPSERVER_RUNAS`. Missing any value returns
before Redis or HTTP clients are constructed. `PACKETFENCE_POLL_INTERVAL_SECONDS` changes only the
beat interval.

### Active Directory automation remains separate

The same Ops Job mechanism was attempted for Active Directory automation, but the PAM VLAN cannot
currently reach the server VLAN over WinRM under the applicable cross-VLAN network policy. Enabling
that traffic requires a firewall rule change outside WardHound and outside this stage's control.
AD automation is intentionally excluded here and will be revisited as a separate stage after that
network ACL change, rather than being represented as implemented or silently routed around PAM.

## Consequences

PacketFence quarantine state can now be collected continuously without a direct PacketFence or SSH
credential, and every command stays brokered and audited by JumpServer. Redis loss can replay the
current quarantine snapshot, while a failed WardHound ingestion cannot silently mark a MAC as
alerted. Asset rename, account removal, Ops feature disablement, job failure, or timeout causes the
cycle to fail visibly without changing quarantine state.

The generic Ops client creates a reusable audited transport, but this decision authorizes only the
read-only PacketFence quarantine query. Future AD use remains contingent on the pending ACL and its
own separately reviewed command, permissions, idempotency, and safety design.
