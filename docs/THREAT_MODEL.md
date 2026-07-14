# WardHound Threat Model

WardHound is itself a high-value security target. A production deployment aggregates normalized
NAC, PAM, directory, and firewall evidence, correlated incidents, AI conclusions, and response
audit history. Compromise could expose organization-wide identities, assets, access patterns,
incident timelines, defensive controls, and response readiness. Modification or deletion could
also conceal an intrusion or manufacture misleading incidents.

## Trust boundaries and primary risks

- The dashboard API currently uses one static `WARDHOUND_API_KEY`. Leakage grants the bearer read
  access to all retained incidents and evidence and the ability to submit, approve, or reject
  response actions as a trusted operator. The response engine still enforces approval for
  privileged actions, but a stolen key lets the attacker impersonate the approver, so the gate is
  not an independent authentication factor. Production needs per-user identity, short-lived
  credentials, role separation, revocation, and attributable approval records.
- Collector input crosses from independently managed security systems into WardHound. A
  compromised source can send false evidence, exhaust storage or correlation capacity, and embed
  prompt-injection text in fields later included in an AI prompt. Structured output validation and
  constrained action types limit malformed output, but they do not prove that an AI recommendation
  is trustworthy. The decisive mitigation is architectural: AI output never executes remediation;
  a human must review evidence and approve every security-state change. Source authentication,
  input limits, provenance, and explicit treatment of event text as untrusted data remain required.
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
