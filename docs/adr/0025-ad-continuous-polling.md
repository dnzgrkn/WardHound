# ADR 0025: Active Directory continuous polling through JumpServer Ops jobs

- Status: Accepted — implemented, live validation pending
- Date: 2026-07-20

## Context

ADR 0021 validated Active Directory Event ID 4625 ingestion from real Security log data by running
`scripts/export-ad-security-events.ps1` on the domain controller and passing its JSON through the
existing `ActiveDirectoryCollector`. That proof established the `Get-WinEvent` query and named XML
field extraction, but the export-and-ingest bridge remained manual.

JumpServer's audited Ops Job API is the intended continuous transport. Earlier attempts using
`shell` and `raw` were rejected as unsuitable for the Windows asset's SSH/cmd connection method.
After a `winrm` protocol was added to the asset and `winrm quickconfig -quiet` was run on the domain
controller, `win_shell` passed the module-suitability check. Subsequent commands timed out without
output. The suspected cause is cross-VLAN WinRM connectivity between the PAM and server VLANs: the
same pending pfSense ACL gap ADR 0024 identified for Active Directory.

## Decision

### Audited WinRM execution with the validated query

Celery beat publishes `app.tasks.active_directory.poll_active_directory` every 300 seconds by
default. Each bounded synchronous invocation owns one `asyncio.run()` loop. It resolves the domain
controller's configured JumpServer asset name, creates an instant `win_shell` job, polls it to a
finite timeout, and cleans the captured execution log using the existing Ops client.

The PowerShell command is a single string and uses only the query proven by
`scripts/export-ad-security-events.ps1`: local Security log Event ID 4625, `.ToXml()`, and the named
fields `EventID`, `Computer`, `TargetUserName`, `TargetDomainName`, `TimeCreated`, and `IpAddress`.
The only adaptations are an ISO 8601 UTC `$since` value instead of an hours lookback and compressed
JSON array output to stdout instead of a file. `win_shell` already runs PowerShell, so no nested
`powershell -Command` wrapper is used. Event IDs 4740 and 4728 remain excluded because their XML
field names were not validated against live Security log data.

Each record passes through the unmodified `ActiveDirectoryCollector.process()` path before being
posted to `/api/v1/events`.

### Redis watermark and retry boundary

Redis key `wardhound:collectors:ad:last_successful_poll` stores the UTC cutoff of the most recent
successful cycle. With no watermark, `AD_INITIAL_LOOKBACK_SECONDS` provides a bounded 300-second
default lookback. The remote query starts at the watermark inclusively because Windows filtering
may return the boundary event; WardHound then enforces the half-open lower boundary locally as
`since < occurred_at <= cutoff`.

The watermark advances only after a non-empty batch is accepted by `/api/v1/events`, or after a
successful empty cycle. Job, parsing, normalization, or ingestion failure leaves it unchanged, so
the same window is retried.

The task is gated by five non-empty values: the JumpServer base URL and AccessKey pair plus
`AD_JUMPSERVER_ASSET_NAME` and `AD_JUMPSERVER_RUNAS`. Missing any value returns before Redis or HTTP
clients are constructed. These last two values identify a JumpServer-managed asset and command
account; they are not direct AD/LDAP credentials. The separate `AD_LDAP_*` settings govern the
account-disablement response action and are unrelated to this read path. `AD_POLL_INTERVAL_SECONDS`
changes only the beat interval.

## Consequences

### Implemented, but live end-to-end delivery is unconfirmed

**A successful live `win_shell` poll producing output from the real domain controller was never
observed before this stage was written.** The transport follows the proven JumpServer Ops Job
pattern, the module-compatibility issue was resolved, and the embedded `Get-WinEvent`/XML logic was
already validated independently against real Event ID 4625 data. That makes the implementation
well-founded, but it is not an end-to-end validation claim.

The suspected blocker is cross-VLAN WinRM connectivity under the pending pfSense ACL change already
flagged for AD in ADR 0024. Internship lab access ended before that network change could be
confirmed. To move this status from “implemented, unconfirmed” to “validated,” an authorized
operator must permit and verify the required WinRM path, run one configured live poll cycle through
JumpServer, observe real Event ID 4625 JSON in the audited job output and the resulting normalized
events accepted by WardHound, and record that evidence with the same rigor ADR 0021 used for the
PacketFence and JumpServer live validation.

Until then, missing configuration safely produces a logged skip with zero AD-Ops network calls.
Configured transport failures remain visible and do not advance the watermark. No direct domain
controller credential, real asset name, run-as account, hostname, or address is stored in the
repository.
