# WardHound

*Tracing enterprise security incidents back to root cause.*

WardHound is a security event correlation, root-cause analysis, and response-orchestration MVP for operators working across NAC, PAM, Active Directory, and firewall infrastructure. It turns normalized signals from otherwise separate controls into explainable incidents, deterministic risk scores, and reviewable response requests.

> **What this is—and is not:** the deterministic correlation, policy, and risk engines are implemented; collector parsing and normalization are tested against sanitized real-world formats; AI analysis is on-demand, typed, and evidence-cited; the React dashboard, REST/WebSocket API, and Prometheus/Grafana/Jaeger observability stack run together. This is not yet a production deployment. Collector transports are not continuously scheduled. Four response handlers remain human-approval-gated simulations. PacketFence quarantine, on-premises Active Directory account disablement, Cisco FMC blocklist membership, and JumpServer session termination are simulated by default and become real only when every integration-specific configuration signal and separate real-execution flag are set. FMC membership changes remain pending until an operator deploys them to managed devices.

The deliberate split is simple: rules decide what correlates and how risk is scored; AI explains the retained evidence but cannot emit arbitrary commands; a human must approve security-state changes; external mutation is disabled unless its integration-specific safety gate is explicitly satisfied.

## Architecture

```mermaid
flowchart LR
    Sources["NAC / PAM / AD / firewall events"]
    Collectors["Collectors<br/>tested parsing + normalization logic<br/>transport scheduling not wired"]
    Normalize["NormalizedEvent contract"]
    Engines["Correlation → policy → risk<br/>deterministic engines"]
    Store["Event + incident + analysis stores<br/>IN-MEMORY / lost on restart"]
    AI["AI analysis engine<br/>on demand / structured output"]
    Response["Response engine<br/>human approval required<br/>PacketFence + AD + FMC + JumpServer gated real modes"]
    Dashboard["Dashboard<br/>REST + WebSocket"]
    Infra[("PostgreSQL + Redis + Celery<br/>durable infrastructure present<br/>not connected to incident state")]
    Telemetry["Cross-cutting telemetry<br/>Prometheus + Grafana + Jaeger"]

    Sources --> Collectors --> Normalize --> Engines --> Store
    Store --> AI --> Response --> Dashboard
    Store --> Dashboard
    Infra -. "health / infrastructure only" .-> Store
    Collectors -.-> Telemetry
    Engines -.-> Telemetry
    AI -.-> Telemetry
    Response -.-> Telemetry
    Dashboard -.-> Telemetry

    classDef memory fill:#fff3cd,stroke:#a66f00,color:#332200;
    classDef simulated fill:#fde2e2,stroke:#a12828,color:#3b1010;
    classDef durable fill:#dff3e4,stroke:#26733a,color:#102d18;
    class Store memory;
    class Response simulated;
    class Infra durable;
```

Legend: yellow is process-local state, red is safety-gated response behavior, and green is durable infrastructure. A green service does not imply that the current incident workflow persists to it.

## Run the demo

Prerequisites are Docker with Docker Compose and available ports 3000, 3001, 8000, 9090, and 16686.

1. Copy [`.env.example`](.env.example) to `.env`.
2. Replace every required placeholder in that local file. Keep `ANTHROPIC_API_KEY` empty if AI analysis is not needed; do not commit `.env`.
3. Build and start the stack:

   ```bash
   docker compose up --build
   ```

4. Open the dashboard at <http://localhost:3000> and choose **Load demo**.

The button creates a fully synthetic AD failure, PacketFence quarantine, and JumpServer session chain in the browser, then submits those already-normalized events through the real correlation, policy, and risk pipeline. It produces a correlated incident without real collector input. Without an Anthropic key, you can inspect the incident and use realtime updates; the dashboard cannot start its recommendation-driven response workflow because recommendations come from AI analysis.

Set `ANTHROPIC_API_KEY` in `.env`, restart the API, open the synthetic incident, and explicitly request analysis to invoke the configured Anthropic model. A successful analysis exposes its recommended actions in the dashboard; submitting one creates an audit record. Privileged actions require approval. With no integration settings, quarantine, disable-user, block-IP, and close-session remain the same simulations as before. PacketFence is real only when `PACKETFENCE_BASE_URL`, `PACKETFENCE_API_TOKEN`, the tenant-specific `PACKETFENCE_ISOLATION_SECURITY_EVENT_ID`, and `PACKETFENCE_REAL_EXECUTION=true` are all set. Active Directory disablement is real only when `AD_LDAP_URL`, `AD_BIND_DN`, `AD_BIND_PASSWORD`, `AD_USER_SEARCH_BASE_DN`, and `AD_REAL_EXECUTION=true` are all set. FMC blocklist membership is real only when `FMC_BASE_URL`, `FMC_USERNAME`, `FMC_PASSWORD`, `FMC_BLOCKLIST_NETWORK_GROUP_ID`, and `FMC_REAL_EXECUTION=true` are all set; an FMC deployment remains an explicit operator responsibility before enforcement. JumpServer termination is real only when `JUMPSERVER_BASE_URL`, `JUMPSERVER_API_TOKEN`, and `JUMPSERVER_REAL_EXECUTION=true` are all set; WardHound confirms `is_finished` after the kill task is accepted. The other four handlers remain simulated. If the Anthropic key is empty, the analysis request returns a clear `503 analysis_not_configured`; the deterministic incident demo remains functional.

This is a **local-config demo**, not a literal no-configuration startup: Compose intentionally refuses to start until the required local database, broker, API-key, and Grafana values referenced by `.env.example` exist. The API key is shared by the frontend and backend and is suitable only for this single-operator environment.

### Exposed surfaces

| Surface | Address | Purpose |
| --- | --- | --- |
| Dashboard | <http://localhost:3000> | Incident triage, demo loading, analysis, and response approvals |
| API / OpenAPI | <http://localhost:8000/docs> | Interactive REST API documentation |
| Grafana | <http://localhost:3001> | Provisioned WardHound operational dashboard |
| Prometheus | <http://localhost:9090> | Metrics scraping and queries |
| Jaeger | <http://localhost:16686> | Distributed trace exploration |
| Raw API metrics | <http://localhost:8000/metrics> | Prometheus scrape endpoint |

`/metrics` is intentionally unauthenticated for private-network Prometheus scraping. Any non-local deployment must isolate it at the network boundary. Grafana, Prometheus, and Jaeger also expose operational security data and require production access controls.

To stop the stack, run `docker compose down`. Add `--volumes` only when you intentionally want to delete the local PostgreSQL and Grafana volumes; WardHound incident state is already lost whenever the API process restarts.

### Frontend development

For an independent Vite development server, copy `frontend/.env.example` to `frontend/.env.local`, use the same API key as the backend, then run:

```bash
cd frontend
npm install
npm run dev
```

Frontend quality commands are `npm run lint`, `npm run typecheck`, `npm run test:run`, and `npm run build`.

### Identity setup

Auth0 is optional for loading and viewing the zero-account demo. Without Auth0 configuration, the
static `WARDHOUND_API_KEY` still authorizes demo event ingestion, incident reads, on-demand
analysis, action-history reads, and realtime WebSocket notifications. Requesting, approving, or
rejecting a response action requires an Auth0 access token.

To enable privileged actions on an Auth0 free-tier tenant:

1. In **Applications → APIs**, create an API named `WardHound API`. Use a URI-style identifier such
   as `https://wardhound-api.example` and keep the signing algorithm at RS256. Enable **RBAC** and
   **Add Permissions in the Access Token**.
2. Add API permissions `request:actions` and `approve:actions`.
3. In **User Management → Roles**, create an `analyst` role with `request:actions`. Create an
   `approver` role with both permissions, then assign test users to the appropriate role.
4. In **Applications → Applications**, create a **Single Page Application** for the React
   dashboard. The Auth0 React SDK is a public browser client and must not use a client secret; a
   Regular Web Application is not appropriate without a server-side backend-for-frontend.
5. Configure Allowed Callback URLs, Allowed Logout URLs, and Allowed Web Origins as
   `http://localhost:3000`. Copy the application Client ID and tenant domain.
6. Set `AUTH0_DOMAIN`, `AUTH0_AUDIENCE`, and `AUTH0_CLIENT_ID` in the root `.env`. Compose passes
   the public values to the frontend as `VITE_AUTH0_DOMAIN`, `VITE_AUTH0_AUDIENCE`, and
   `VITE_AUTH0_CLIENT_ID`. For standalone frontend development, set those `VITE_` values in
   `frontend/.env.local` using `frontend/.env.example` as the template.

The domain value excludes `https://`; the audience must exactly match the API identifier. No Auth0
client secret belongs in either frontend environment or source control. These steps follow Auth0's
[FastAPI API quickstart](https://auth0.com/docs/quickstart/backend/fastapi),
[React SPA quickstart](https://auth0.com/docs/quickstart/spa/react), and
[Core RBAC guidance](https://auth0.com/docs/manage-users/access-control/configure-core-rbac/roles).

## Validation case study

WardHound's collector formats and investigation workflow were validated against sanitized PacketFence NAC, JumpServer PAM, and Active Directory Tiering event data from a mid-sized enterprise Zero Trust engagement. No client identity or production identifier is included in this repository. The concrete evidence chains and outcomes are documented in the [anonymized case study](docs/CASE_STUDY.md).

## Engineering principles and decisions

WardHound keeps deterministic security decisions separate from probabilistic explanation, uses typed immutable contracts between layers, injects infrastructure behind small interfaces, and requires human review before any privileged response. The decision history records the trade-offs:

- [ADR 0001](docs/adr/0001-record-architecture-decisions.md) — recording significant architecture decisions.
- [ADR 0002](docs/adr/0002-event-schema-and-collector-interface.md) — shared event schema, entity model, and collector boundary.
- [ADR 0003](docs/adr/0003-collector-parsing-assumptions.md) — verified PacketFence, JumpServer, and AD parsing formats.
- [ADR 0004](docs/adr/0004-correlation-policy-risk-design.md) — deterministic correlation, policy evaluation, and risk scoring.
- [ADR 0005](docs/adr/0005-ai-analysis-engine-design.md) — structured, on-demand, evidence-cited AI analysis.
- [ADR 0006](docs/adr/0006-response-engine-design.md) — approval workflow and simulation-only response boundary.
- [ADR 0007](docs/adr/0007-incident-api-design.md) — incident API, in-memory stores, static-key auth, and realtime updates.
- [ADR 0008](docs/adr/0008-observability-and-hardening.md) — bounded telemetry, tracing, metrics, and test hardening.
- [ADR 0010](docs/adr/0010-auth0-identity-federation.md) — Auth0 federation, API permissions, and attributable response decisions.
- [ADR 0011](docs/adr/0011-real-packetfence-integration.md) — safety-gated real PacketFence quarantine.
- [ADR 0012](docs/adr/0012-real-active-directory-disable.md) — confirmed, safety-gated Active Directory account disablement.
- [ADR 0013](docs/adr/0013-real-fmc-block-ip.md) — confirmed Cisco FMC blocklist membership with explicit deployment status.
- [ADR 0014](docs/adr/0014-real-jumpserver-close-session.md) — confirmed, safety-gated JumpServer session termination.

See the [product specification](docs/SPEC.md), [roadmap](docs/ROADMAP.md), and [threat model](docs/THREAT_MODEL.md) for the wider design and explicitly deferred production work.
