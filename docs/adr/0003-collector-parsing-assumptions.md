# ADR 0003: Collector Parsing Assumptions

- Status: Accepted provisionally
- Date: 2026-07-10

## Context

Stage 2 needs deterministic collector implementations before representative source logs are
available. The formats below are working assumptions, not confirmed vendor contracts. They must
be validated against sanitized internship logs before the correlation engine relies on them.

## Decision

### PacketFence

PacketFence input is assumed to be an RFC5424 syslog line. The RFC5424 sender hostname becomes
`RawEvent.source_host`. After the optional structured-data block, the message is assumed to contain
an event keyword followed by whitespace-separated `key=value` fields. Quoted values are accepted.
Recognized optional keys are `mac`/`mac_address`, `ip`, `hostname`, `role`, and `vlan`; a valid MAC
address is required for normalization. Expected event keywords are `auth_failed`,
`device_unknown`, `device_registered`, `device_quarantined`, and `vlan_assigned`, with a small set
of documented aliases in code.

### JumpServer

The polling endpoint is assumed to return a JSON list of flat objects. Each object has
`event_type`, `username`, and an ISO 8601 `timestamp`; optional fields include `source_host`,
`target_host`, `target_ip`, `session_id`, `command`, and `reason`. Event names are assumed to be
`session_started`, `session_ended`, `privileged_command_executed`,
`session_anomaly_detected`, or `auth_failed`. A target hostname takes precedence over a target IP
when both are present. The illustrative poller sends `since` as an ISO 8601 query parameter.

### Active Directory

Windows Security events are assumed to have already been converted from XML/EVTX into flat
dictionaries. `EventID` and `Computer` (or `source_host`) are required. `TimeCreated` is an ISO 8601
timestamp. Events 4625 and 4740 identify the account with `TargetUserName`; event 4728 uses
`MemberName`. `TargetDomainName` supplies the optional domain. Event-specific context may use
`IpAddress`, `CallerComputerName`, and `GroupName`.

## Consequences

These parsers are intentionally strict enough to expose format drift as `ValueError` instead of
silently producing misleading normalized events. Real PacketFence, JumpServer, and AD samples may
require field aliases, nested-envelope handling, or timestamp changes after validation.

Password-spray and tier-violation detection are deliberately excluded: they require correlation
across multiple events and belong to the Stage 3 correlation engine.
