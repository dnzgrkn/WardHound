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
