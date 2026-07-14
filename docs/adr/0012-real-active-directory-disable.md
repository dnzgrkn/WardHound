# ADR 0012: Safety-gated Active Directory account disablement

- Status: Accepted
- Date: 2026-07-14

## Context

WardHound's `DISABLE_USER` handler previously described a hypothetical Active Directory change.
The read path consumes on-premises Windows Security events, so the matching write boundary is
self-hosted Active Directory over LDAP, not Azure AD or Entra ID.

Account disablement is higher risk than Stage 11's PacketFence quarantine. Network isolation
restricts one device's connectivity; disabling a directory identity can remove email, SSO, VPN,
PAM, and application access everywhere that identity is trusted. The integration must therefore
fail closed, preserve human approval, use narrowly delegated credentials, and verify resulting
directory state rather than treating request acceptance as success.

## Decision

### LDAP operation and confirmation

WardHound uses `ldap3` over LDAPS only, with certificate validation and explicit ten-second connect
and receive timeouts. It binds with a dedicated service identity, searches one configured subtree
for an escaped `sAMAccountName`, and requires exactly one user object. The client reads the current
integer `userAccountControl`, ORs in `ACCOUNTDISABLE` (`0x2`), and writes the value with
`MODIFY_REPLACE`. An account that already has the bit is a successful idempotent no-op.

A successful modify return is not sufficient. The client performs a second LDAP search directly on
the resolved user DN and reports success only when the fresh `userAccountControl` value contains
`ACCOUNTDISABLE`. Bind failure, connection failure, missing or ambiguous users, modify failure, and
confirmation failure become safe `ActiveDirectoryError` messages. Bind credentials and directory
server messages are excluded from exceptions and audit results.

### Synchronous library behind an async boundary

`ldap3` is a synchronous library with no native asyncio driver. The complete bind, search, modify,
confirmation-read, and unbind transaction runs in one `asyncio.to_thread` call, while the response
handler remains async. This is not the Stage 9 error: that implementation wrapped an already-async
database driver in a thread and nested event loop, then blocked FastAPI waiting for it. Here there
is no nested loop and the unavoidable blocking LDAP I/O is moved off the API event-loop thread.
Keeping one transaction in one worker also avoids moving a connection between threads mid-operation.

### Five-signal execution gate

Real execution requires all five environment signals to be non-empty or explicitly enabled:

1. `AD_LDAP_URL`, using `ldaps://`;
2. `AD_BIND_DN`;
3. `AD_BIND_PASSWORD`;
4. `AD_USER_SEARCH_BASE_DN`; and
5. `AD_REAL_EXECUTION=true`.

Every other combination returns the original simulation description without constructing a client
or making a network call. Human approval and Auth0 authorization remain mandatory ahead of this
gate. Real audit results use `mode=real`, `operation=disable_account`, confirmation status, and the
safe distinction between already disabled and newly disabled. Credentials, DNs, and LDAP response
content are not retained in result details.

### Deliberately narrow directory scope

The client searches one base DN and does not route across domains or forests. The bind identity must
be delegated only the `userAccountControl` write needed on OUs containing eligible accounts; it
must not be Domain Admin or equivalent. Disablement is intentionally the only real AD mutation in
this stage. The remaining response handlers are unaffected.

## Consequences

With no AD configuration, the existing demo and disable-user handler remain simulation-only and do
not load credentials or contact LDAP. With all signals enabled, an approved action can cause an
identity-wide lockout, so OU eligibility, delegation, monitoring, and recovery procedures are
deployment responsibilities. Tests use ldap3's `MOCK_SYNC` strategy and make no directory or
network calls; one regression test makes modify return success without changing state and proves
the confirmation read rejects that false success.
