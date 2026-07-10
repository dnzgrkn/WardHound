# WardHound — Agent Instructions (Claude Code)

You are acting as principal software architect on this repo. Treat this as enterprise-grade open-source security tooling, not a demo.

## What this is

WardHound — AI-powered Security Event Correlation, Root Cause Analysis, and Response Orchestration platform for enterprise infrastructure (NAC, PAM, Active Directory, firewalls). NOT endpoint AV, NOT malware analysis, NOT pentesting. It sits between infrastructure event sources and security operators: collects events, normalizes them, correlates them into incidents, scores risk, explains probable root cause via AI (structured output only, no free text), and recommends — never autonomously executes — remediation actions.

Tagline: *tracing enterprise security incidents back to root cause.* Full spec, event taxonomy, and architecture diagram: see `docs/SPEC.md`. Sprint plan: see `docs/ROADMAP.md`.

## Stack

Python 3.12, FastAPI, Pydantic v2, SQLAlchemy, PostgreSQL, Redis, Celery, Docker Compose, JWT auth. AI via Anthropic Claude + Instructor for structured outputs. Frontend: React, TypeScript, Tailwind, shadcn/ui, WebSockets. Observability: Prometheus, Grafana, OpenTelemetry. Testing: pytest, httpx, ruff, mypy.

## Engineering principles (non-negotiable)

- Enterprise quality over fast code. No unnecessary abstractions, no over-engineering.
- Typed Python everywhere, async by default, dependency injection, SOLID.
- Every module independently testable. Every important component has unit tests.
- Every architectural decision with real trade-offs gets an ADR in `docs/adr/` (use the template in `docs/adr/0001-record-architecture-decisions.md`).
- AI output is ALWAYS a Pydantic model. Never free-form text from the AI analysis engine.
- Response Engine actions are simulated by default. Anything privileged requires human-in-the-loop approval — this is a credibility requirement, not a nice-to-have.
- If a design isn't scalable or secure, say so directly and explain why, don't silently comply.

## Confidentiality (critical)

This project is validated against a real enterprise Zero Trust environment (NAC/PAM/AD) the author has access to via an internship. When writing collectors, sample event fixtures, docs, or tests:
- Never hardcode or commit real hostnames, IPs (beyond generic RFC1918 examples), usernames, SNMP/RADIUS secrets, or any client-identifying detail.
- Sample/test event data must be synthetic or clearly genericized ("enterprise-client-a", "10.20.x.x" placeholders).
- If you are given real log samples to work from during a session, extract the *shape*/schema, not the literal values, into anything that gets committed.

## Working agreement

- This repo is being built in parallel with a Codex CLI agent working in a separate git worktree. Stay inside the module boundaries assigned to you in your task prompt — don't touch files owned by the other track unless explicitly asked to.
- Small, reviewable commits. Conventional commit messages (`feat:`, `fix:`, `docs:`, `test:`).
- Before marking a task done: `ruff check .`, `mypy .`, `pytest` must pass.
