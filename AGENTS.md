# WardHound — Agent Instructions (Codex)

## What this is

WardHound — AI-powered Security Event Correlation, Root Cause Analysis, and Response Orchestration platform for enterprise infrastructure (NAC, PAM, Active Directory, firewalls). Tagline: *tracing enterprise security incidents back to root cause.* Full spec: `docs/SPEC.md`. Sprint plan: `docs/ROADMAP.md`.

## Stack

Python 3.12, FastAPI, Pydantic v2, SQLAlchemy, PostgreSQL, Redis, Celery, Docker Compose. Testing: pytest, httpx, ruff, mypy. Frontend (later phase): React, TypeScript, Tailwind, shadcn/ui.

## Rules

1. Typed Python everywhere. No `Any` unless truly unavoidable — justify it in a comment if used.
2. Every file you create or touch must pass `ruff check .` and `mypy .` before you consider the task done.
3. Write tests alongside code, not after. `pytest` must pass.
4. Do not invent scope beyond what the task prompt asks for. If the task is "write the Docker Compose skeleton," don't also start writing business logic.
5. Stay inside the file/directory boundaries given in your task prompt. A parallel Claude Code agent is working in the same repo on a different git worktree/branch — do not modify files outside your assigned scope.
6. Never commit real hostnames, IPs (beyond generic RFC1918 placeholders), usernames, or secrets. All fixture/sample data must be synthetic.
7. Conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `chore:`.
8. If a requirement is ambiguous, make the most conventional/boring choice and note the assumption in the PR description — don't block waiting for clarification on low-stakes decisions.

## Definition of done for any task

- Code typed and passing `ruff` + `mypy`
- Tests written and passing
- No secrets or client-identifying data committed
- Scope matches the task prompt exactly, nothing extra
