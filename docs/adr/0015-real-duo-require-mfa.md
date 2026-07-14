# ADR 0015: Safety-gated real Duo verification challenge

- Status: Accepted
- Date: 2026-07-14

## Context

WardHound's `REQUIRE_MFA` handler previously described a future identity-provider action. Auth0 is
not that provider: ADR 0010 uses Auth0 solely to authenticate WardHound analysts and approvers.
Incident subjects are workforce identities sourced from on-premises Active Directory, and Duo is a
separate enterprise MFA control commonly deployed alongside NAC and PAM.

Duo's Admin Panel has a **Require 2FA on Next Auth** control that resets remembered-device
sessions. The current public Admin API documentation does not expose that reset operation. Using an
undocumented panel endpoint would be brittle, while toggling a user through disabled and active
states would create a lockout window, could strand the user if reactivation failed, and is not
permitted for some directory-synchronized users. WardHound must not claim either workaround is a
supported next-access control.

The documented Admin API does expose a verification push and a corresponding result lookup. This
stage therefore implements an immediate, explicitly confirmed step-up challenge. It is a narrower
semantic than resetting all remembered sessions and is named honestly in the audit record.

## Decision

### Verified operation and confirmation

WardHound resolves the raw AD username with
`GET /admin/v1/users?username=<username>` and requires exactly one active, enrolled Duo user. It
selects an activated phone whose capabilities include `push`, then calls
`POST /admin/v1/users/{user_id}/send_verification_push` with form parameter `phone_id`. The client
polls `GET /admin/v1/users/{user_id}/verification_push_response?push_id=<push_id>` for a bounded ten
seconds and succeeds only when Duo reports `result=approve`.

After approval, the client re-fetches `GET /admin/v1/users/{user_id}` and confirms the expected
identity remains active and enrolled. The verified state change is the push result moving to
approved; user status is intentionally not mutated. A denied, fraudulent, expired, still-waiting,
or malformed result is a failed action. This flow sends one push only—polling never sends another.

Real audit results use `mode=real`, `operation=send_verification_push`, and
`verification_confirmed=true`. This does not claim that remembered-device cookies were revoked or
that every future application access will prompt again.

### Duo request signing

Every request follows Duo's documented Admin API signing scheme. WardHound creates the RFC 2822
`Date` header and a five-line ASCII canonical representation containing, in order: date, uppercase
HTTP method, lowercase API hostname, path, and lexicographically sorted URL-encoded parameters.
GET parameters come from the query string; POST parameters use the form body. An empty parameter
set still contributes the fifth blank line.

The client computes the hexadecimal HMAC-SHA1 digest using the secret key, then sends HTTP Basic
authentication with the integration key as username and the digest as password. Tests independently
reconstruct the canonical value and authorization header for all four request types rather than
calling the production signer as their oracle.

### Four-signal execution gate

Real execution requires all four signals:

1. a valid `DUO_API_HOSTNAME` under `duosecurity.com`;
2. a non-empty `DUO_INTEGRATION_KEY`;
3. a non-empty `DUO_SECRET_KEY`; and
4. `DUO_REAL_EXECUTION=true`.

Every partial configuration retains the original no-network simulation path. Auth0 approval remains
an independent upstream requirement and no Auth0 setting or operator identity is reused for Duo.
The Admin API integration needs only resource read/write permissions needed to retrieve users and
send verification pushes.

## Consequences

With no Duo settings, the demo and require-MFA handler behave exactly as before. With the gate
enabled, an approved action sends a real push to the incident subject. This does not disable the
account and cannot itself lock out a user who lacks a working MFA device: the action instead fails
because no activated push-capable phone exists or because approval is not received. Access may
still be unavailable under the protected application's own MFA policy, which is an existing Duo
deployment property rather than a mutation made here.

Unsolicited pushes create fatigue and social-engineering risk. Human approval, one push per action,
bounded result polling, least-privilege credentials, and explicit real-execution configuration are
the primary controls. Operators must protect and rotate both Duo keys and restrict WardHound egress
to the configured API hostname.

## Sources

- [Duo Admin API authentication and user operations](https://duo.com/docs/adminapi)
- [Duo user administration and remembered-device reset](https://duo.com/docs/administration-users)

