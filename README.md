# WardHound

*Tracing enterprise security incidents back to root cause.*

AI-powered Security Event Correlation, Root Cause Analysis, and Response Orchestration platform for enterprise infrastructure — NAC, PAM, Active Directory, and firewall event sources.

> Status: Active MVP — collectors, correlation, policy/risk scoring, structured AI analysis,
> simulated response approvals, API, and dashboard are implemented.

## What this is

Enterprise security teams drown in disconnected logs from NAC, PAM, and identity systems. WardHound sits between that infrastructure and the operator: it collects raw events, normalizes them into a common schema, correlates them into incidents, scores risk, uses an LLM (via structured output only — no free-form AI text) to explain probable root cause, and recommends remediation actions that require human approval before anything privileged executes.

This is not an AI wrapper or a chatbot. It's a rule-based correlation and policy engine with a constrained, typed AI layer bolted on for explanation and triage — deliberately conservative about what the AI is allowed to decide.

## Architecture

```
Enterprise Events (PacketFence / JumpServer / AD / Firewall)
      |
  Collectors
      |
Normalization Layer  -->  common NormalizedEvent schema
      |
Correlation Engine    -->  time-windowed incident grouping
      |
  Policy Engine        -->  known violation patterns
      |
   Risk Engine          -->  deterministic weighted scoring
      |
AI Analysis Engine     -->  structured root-cause + confidence (Claude + Instructor)
      |
 Response Engine        -->  simulated actions, human-in-the-loop
      |
   Dashboard (React)
```

Full spec: [`docs/SPEC.md`](docs/SPEC.md). Build roadmap: [`docs/ROADMAP.md`](docs/ROADMAP.md). Design decisions: [`docs/adr/`](docs/adr/).

## Stack

Python 3.12 · FastAPI · Pydantic v2 · SQLAlchemy · PostgreSQL · Redis · Celery · Docker Compose · Anthropic Claude + Instructor · React/TypeScript/Tailwind · Prometheus/Grafana/OpenTelemetry.

## Getting started

Copy `.env.example` to `.env`, replace the placeholder passwords and dashboard API key, then start
the full stack:

```bash
docker compose up --build
```

The FastAPI service is available at `http://localhost:8000`; the dashboard is available at
`http://localhost:3000`. The dashboard includes a **Load demo** control that submits a fully
synthetic NAC/identity/PAM evidence chain through the real correlation pipeline.

### Frontend development

The React frontend is an independent Vite package. Copy `frontend/.env.example` to
`frontend/.env.local` and use the same API key configured for the backend:

```bash
cd frontend
npm install
npm run dev
```

Frontend quality commands are `npm run lint`, `npm run typecheck`, `npm run test:run`, and
`npm run build`. The development server runs on port 3000 and talks directly to the API and
WebSocket endpoints configured through `VITE_API_BASE_URL`, `VITE_WS_BASE_URL`, and
`VITE_API_KEY`.

## A note on validation

This project's correlation and normalization logic is being developed and validated against a real enterprise Zero Trust deployment (NAC/PAM/AD Tiering) via an internship engagement. No client-identifying data — hostnames, IPs beyond generic examples, usernames, secrets — appears anywhere in this repo. See `CLAUDE.md`/`AGENTS.md` for the confidentiality rules contributors (human or AI) must follow.
