# ADR 0010: Auth0 identity federation

- Status: Accepted
- Date: 2026-07-14

## Context

WardHound's static dashboard API key preserves a useful zero-account portfolio demo, but it cannot
identify an operator or separate response requesters from approvers. A caller could previously
supply `decided_by` in an approval request body, so the audit label was not evidence of identity.
Response actions are currently simulated, but their authorization and audit boundary should match
the enterprise IAM and Zero Trust premise before real integrations are introduced.

## Decision

### Federation and token validation

Auth0 is the external OIDC/OAuth 2.0 authorization server. WardHound does not issue passwords,
sessions, or JWTs and does not manage signing keys. The API uses Auth0's FastAPI API SDK to validate
Bearer access-token signature, issuer, audience, and lifetime against the configured tenant. Tenant
domain, API audience, and public application client ID come only from environment configuration.

This avoids a homegrown identity system and exercises the same federation boundary expected in an
enterprise deployment. Auth0 tenant availability and JWKS retrieval become external dependencies;
privileged routes fail closed when identity configuration or validation is unavailable.

The React dashboard is registered as an Auth0 Single Page Application, despite an earlier planning
note calling for a Regular Web Application. The standard Auth0 React SDK is a public browser client
and cannot protect a client secret. A Regular Web Application would require a separate confidential
backend-for-frontend and server-side session design, which is outside this stage. WardHound stores
no Auth0 client secret and never exposes one to Vite.

### Authorization model

Auth0 Core RBAC maps roles to API permissions included in access tokens:

- `analyst` receives `request:actions` and may submit a recommended response action;
- `approver` receives `request:actions` and `approve:actions` and may also approve or reject.

The backend authorizes permissions, not role names. Permissions state the API capability directly,
allow roles to evolve without code changes, and avoid a custom namespaced role claim or Auth0
Action. A valid token without the required permission receives HTTP 403; a missing or invalid token
receives HTTP 401.

### Demo and identity boundary

The static key continues to authorize `POST /events`, incident list/detail and action-history reads,
on-demand analysis, and realtime incident WebSocket notifications. These operations keep `docker
compose up` plus **Load demo** useful without an Auth0 account. Action request, approval, and
rejection routes accept Auth0 Bearer identity only; possessing the static key adds no authority on
those routes.

WebSocket messages report server-side state and cannot mutate it, so the existing query-string API
key remains sufficient for this demo notification channel. Adding token refresh and reconnect
behavior to the socket would add complexity without strengthening the privileged mutation boundary.
TLS remains required outside local development because query credentials may be logged.

### Attributable decisions

Approval request bodies no longer contain `decided_by`; rejection bodies contain only the reason.
For both decisions, the API passes the verified access token's `sub` claim to `ResponseEngine`, and
the immutable action snapshot persists that subject as `decided_by`. Clients cannot select or
overwrite the audit identity. Auth0 subject identifiers are stable identifiers, not display names;
resolving friendly operator profiles is deferred.

## Consequences

Reviewers can still load and inspect the synthetic demo with only the local static key. Privileged
actions require a real, attributable Auth0 principal and permission, with analyst/approver duties
separated. CI and unit tests override the token-validation dependency with synthetic principals, so
no tenant credentials or Auth0 network calls are required. The static key remains a material read
and resource-consumption risk, while Auth0 configuration, account lifecycle, MFA, token lifetime,
and role assignment become operational responsibilities of the tenant administrator.
