# WardHound Threat Model

WardHound is itself a high-value security target. A production deployment aggregates normalized
NAC, PAM, directory, and firewall evidence, correlated incidents, AI conclusions, and response
audit history. Compromise could expose organization-wide identities, assets, access patterns,
incident timelines, defensive controls, and response readiness. Modification or deletion could
also conceal an intrusion or manufacture misleading incidents.

## Trust boundaries and primary risks

- The static `WARDHOUND_API_KEY` remains a zero-account demo credential. Leakage grants read access
  to retained incidents and evidence, synthetic demo ingestion, analysis requests, action-history
  reads, and realtime notifications. It cannot request, approve, or reject response actions: those
  routes require a short-lived Auth0 access token with API-specific permissions, and decisions are
  attributed to the verified token subject. The shared key still exposes sensitive evidence and
  can consume correlation, AI-provider, storage, and realtime capacity, so it requires rotation,
  rate limits, TLS, and eventual replacement with identity-aware access for non-demo deployments.
- Collector input crosses from independently managed security systems into WardHound. A
  compromised source can send false evidence, exhaust storage or correlation capacity, and embed
  prompt-injection text in fields later included in an AI prompt. Structured output validation and
  constrained action types limit malformed output, but they do not prove that an AI recommendation
  is trustworthy. The decisive mitigation is architectural: AI output never executes remediation;
  a human must review evidence and approve every security-state change. Source authentication,
  input limits, provenance, and explicit treatment of event text as untrusted data remain required.
- PacketFence quarantine is the first outbound infrastructure-mutation boundary. A compromised or
  over-permissioned API token can apply security events that reassign device access and interrupt
  network connectivity. Real execution therefore requires PacketFence connection settings, a
  tenant-specific `PACKETFENCE_ISOLATION_SECURITY_EVENT_ID`, and the independent
  `PACKETFENCE_REAL_EXECUTION=true` flag; human approval remains mandatory. Use a dedicated
  PacketFence identity restricted to applying the designated isolation security event where API
  roles support that granularity, rotate the token, restrict WardHound egress to the management
  endpoint, and keep the flag false while validating configuration. Deployments that cannot scope
  the identity accept a larger blast radius and should isolate this integration until compensating
  controls are in place.
- Active Directory account disablement has a broader blast radius than PacketFence network
  isolation: disabling an identity can revoke email, SSO, VPN, PAM, and downstream application
  access at once. A compromised bind identity can also lock out many eligible users. Real execution
  requires an LDAPS URL, bind DN and password, one user search base, and the independent
  `AD_REAL_EXECUTION=true` flag, in addition to human approval. The bind identity must never be a
  Domain Admin or equivalent; delegate only the right to update `userAccountControl` on explicitly
  eligible user OUs, restrict the configured search base to those OUs, protect and rotate the
  password, and alert on use of that identity. WardHound confirms the disabled bit with a fresh read
  after modification, but this does not reduce the authorization blast radius of excessive LDAP
  privileges.
- Logs, metrics, and traces cross into separate operational stores. They deliberately contain only
  bounded categories, UUIDs, counts, statuses, and event types—not API keys, full event payloads,
  `extra_attributes`, operator names, hostnames, usernames, or target addresses. Access and
  retention controls must still treat telemetry as sensitive because identifiers and timing can
  reveal incident activity.
- PostgreSQL, Redis, the AI provider, and observability backends are separate trust boundaries.
  Environment variables keep credentials out of source control, but process inspection and a host
  compromise can expose them. Production should use a managed secret store, narrow service
  identities, rotation, egress restrictions, encryption at rest, and tested backup restoration.

## Local-development boundary

The Compose stack is a single-operator demonstration environment. TLS termination, mutual service
authentication, network segmentation, a WAF or rate limiter, multi-tenant isolation, external
secret management, and hardened backup/audit retention are intentionally out of scope locally.
They are deployment requirements for a real environment: expose only the TLS-terminating gateway,
isolate data and observability services on private networks, restrict collector and AI-provider
egress, and protect Jaeger, Prometheus, and Grafana with the same care as the incident API.
