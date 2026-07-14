# ADR 0013: Safety-gated Cisco FMC blocklist membership

- Status: Accepted
- Date: 2026-07-14

## Context

WardHound's `BLOCK_IP` handler previously described a hypothetical firewall deny rule. Directly
creating or reordering Access Control Policy rules would introduce rule-order side effects and give
the integration an unnecessarily broad policy-writing role. A safer SOAR pattern is a human-owned
Network Group already referenced by an existing deny rule; WardHound manages only IP literals in
that object.

FMC separates management-plane object changes from deployment to managed devices. Treating a
successful Network Group PUT as an enforced block would repeat the class of confirmation error
caught in ADR 0011 and avoided in ADR 0012.

## Decision

### Verified FMC contract

For each action, WardHound obtains a fresh token with
`POST /api/fmc_platform/v1/auth/generatetoken`, an empty body, and HTTP Basic credentials. Cisco
returns `X-auth-access-token` and `DOMAIN_UUID` response headers; subsequent requests send the
access token header and use the domain UUID in their paths.

The client fetches and updates the configured object at
`/api/fmc_config/v1/domain/{domainUUID}/object/networkgroups/{id}`. An IP member uses Cisco's
literal shape `{"type": "Host", "value": "10.20.30.40"}`. The client preserves existing object
references, literals, description, and override setting while excluding read-only response
metadata. An exact existing Host literal is an idempotent success. Otherwise the client PUTs the
updated object, re-fetches it, and reports success only when the target literal is present.

The async client uses `httpx.AsyncClient` with a ten-second timeout. TLS verification remains
enabled; deployments using a private CA must install or configure a trusted CA bundle rather than
disable verification. Error response bodies and credentials are never copied into exceptions or
audit records.

### Deployment is deliberately operator-controlled

Cisco documents `GET .../deployment/deployabledevices` as listing devices with configuration
changes ready to deploy, and `POST .../deployment/deploymentrequests` as creating the request that
pushes changes to devices. Network Group membership in FMC is therefore not proof that managed
devices enforce it yet.

WardHound does not create a deployment request in this stage. Correct deployment requires selecting
the affected devices and may include other pending FMC changes; automatically deploying all ready
devices could push unrelated administrator work. Device selection and pending-change approval are
not represented by this action's five configuration signals. Real results consequently include
`membership_confirmed=true` and `enforcement_pending_deploy=true`, and the human-readable result
states that deployment is required. Operators must review and deploy through FMC change control.

### Five-signal execution gate

Real execution requires all five values:

1. `FMC_BASE_URL`, using HTTPS;
2. `FMC_USERNAME`;
3. `FMC_PASSWORD`;
4. `FMC_BLOCKLIST_NETWORK_GROUP_ID`; and
5. `FMC_REAL_EXECUTION=true`.

Every incomplete combination returns the original simulation description and makes no request.
Human approval and Auth0 authorization remain in front of this gate. Audit operation names are
`add_blocklist_member`, with an explicit `mode` distinguishing real and simulated execution.

### Least privilege and scope

The FMC identity should be limited to reading and modifying the pre-provisioned Network Group where
FMC role granularity permits. It should not receive general Access Control Policy, device, or deploy
permissions. WardHound does not create groups, modify deny rules, remove members, select devices, or
deploy configuration in this stage.

## Consequences

With no FMC configuration, the demo and block-IP handler remain simulation-only. With all gate
signals enabled, WardHound can confirm durable FMC object membership but honestly reports that
enforcement is pending deployment. Token failure, missing objects, update failure, malformed object
responses, and failed confirmation reads become clean failed audit snapshots.

The contract and deployment decision were verified against Cisco's official documentation:

- [FMC authentication token generation](https://www.cisco.com/c/en/us/support/docs/security/firepower-management-center/215918-how-to-generate-authentication-token-for.html)
- [FMC Network Group GET/PUT API](https://www.cisco.com/c/en/us/td/docs/security/firepower/10-0/API/REST/firepower_management_center_rest_api_quick_start_guide_10_0/Objects_In_The_REST_API.html)
- [FMC deployment services](https://www.cisco.com/c/en/us/td/docs/security/firepower/770/API/REST/secure_firewall_management_center_rest_api_quick_start_guide_770/Objects_In_The_REST_API.html)
