# WardHound — Product & Architecture Spec

## Vision

WardHound is an AI-powered Security Event Correlation, Root Cause Analysis, and Response Orchestration platform. It is intelligent middleware between enterprise infrastructure and security operators: instead of manually reading thousands of logs, operators receive correlated incidents, AI-generated explanations, and recommended remediation actions.

Scope: network security, identity security, Zero Trust, infrastructure security, NAC, PAM, Active Directory, firewall events, authentication events.
Explicitly out of scope: endpoint antivirus, malware analysis, penetration testing.

## Primary goals

Collect events → normalize → correlate → calculate risk score → detect policy violations → understand enterprise identity relationships → AI-assisted root cause analysis → generate remediation recommendations → (optionally) execute approved automated responses.

## Example event sources

**PacketFence:** Authentication Failed, Unknown Device, VLAN Assignment, Registration, Quarantine.
**JumpServer:** Failed Login, New Session, Privileged Command, Session Recording, Abnormal Session.
**Active Directory:** Failed Authentication, Password Spray, Group Membership Change, Tier Violation, Account Lockout.
**Firewall:** Blocked Traffic, Lateral Movement Attempt, Port Scan, Unexpected East-West Traffic.

## High-level architecture

```
Enterprise Events
      |
  Collectors
      |
Normalization Layer
      |
Correlation Engine
      |
  Policy Engine
      |
   Risk Engine
      |
AI Analysis Engine
      |
 Response Engine
      |
   Dashboard
```

## AI responsibilities

AI is not allowed to blindly generate commands. It must: explain incidents, correlate evidence, identify probable root cause, explain why, estimate confidence, recommend remediation, explain side effects. All AI output is a Pydantic model (Instructor-enforced) — no free-form text.

## Response Engine — possible actions

Quarantine Device, Disable User, Block IP, Close Session, Require MFA, Notify Administrator, Create Incident, Require Manual Approval. All actions are simulated initially; real integrations come later. Anything privileged requires human approval — no autonomous remediation.

## Technology stack

**Backend:** Python 3.12, FastAPI, Pydantic v2, SQLAlchemy, PostgreSQL, Redis, Celery, Docker/Docker Compose. JWT auth.
**AI:** Anthropic Claude, Instructor, structured outputs, Redis-backed vector search.
**Frontend:** React, TypeScript, Tailwind, shadcn/ui, WebSockets for realtime.
**Observability:** Prometheus, Grafana, OpenTelemetry.
**Testing:** pytest, httpx, ruff, mypy.

## Engineering principles

Enterprise-quality engineering, not fast code. No over-engineering, no unnecessary abstractions. Clean architecture, SOLID, dependency injection, typed Python, async by default. Every module independently testable, every important component unit-tested. Every API OpenAPI-documented. Everything runs through Docker Compose. CI/CD via GitHub Actions.

## Repository quality bar

Professional README, architecture diagrams, API documentation, design documents, ADRs, roadmap, issues, milestones, release versions, CI/CD.

## Naming

The project is named **WardHound**. "Ward" (guardian, protector) plus "Hound" (tracker) — a defensive counterpart to offensive AD attack-path tooling like BloodHound: where those tools find paths *in* for an attacker, WardHound finds the path *back to root cause* for a defender. Tagline: "tracing enterprise security incidents back to root cause."

## Confidentiality constraint

This project is being validated against a real enterprise Zero Trust environment the author has production access to (via an internship: PacketFence NAC, 802.1X, JumpServer PAM, AD Tiering). No client-identifying detail — real hostnames, IPs beyond generic RFC1918 examples, usernames, secrets — may ever be committed to this public repo. All fixtures and examples are synthetic or genericized.
