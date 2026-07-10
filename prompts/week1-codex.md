# Week 1 — Track B (Codex): Project skeleton, Docker Compose, CI

Run this in its own worktree/branch: `git worktree add ../wardhound-skeleton feat/project-skeleton`, then `cd` into it and start Codex there.

---

**Prompt to paste into Codex:**

Read AGENTS.md and docs/SPEC.md first for full context. This is Week 1, Track B of WardHound. A second agent (Claude Code) is working in parallel in a different worktree on branch `feat/event-schemas`, building `app/schemas/` and `app/collectors/base.py`. Do not touch those paths — stay strictly in the scope below so our branches merge cleanly.

Your scope for this session:

1. `pyproject.toml`: Python 3.12 project, dependencies for FastAPI, Pydantic v2, SQLAlchemy (async), asyncpg, Redis client, Celery, uvicorn. Dev dependencies: pytest, httpx, ruff, mypy. Configure ruff and mypy (strict-ish: `disallow_untyped_defs = true`).

2. `docker-compose.yml` with services: `api` (FastAPI, builds from a `Dockerfile` you also write), `postgres` (Postgres 16, named volume, healthcheck), `redis` (Redis 7, healthcheck), `worker` (Celery worker, same image as api, depends_on postgres+redis). Use environment variables for all connection strings, provide a `.env.example` with placeholder values — never real secrets.

3. `app/main.py`: FastAPI app factory pattern, CORS middleware, a `/health` endpoint that checks DB and Redis connectivity and returns a typed Pydantic response model, OpenAPI docs enabled at `/docs`.

4. `app/api/health.py`: the health router, separated from `main.py` (routers live in `app/api/`).

5. `.github/workflows/ci.yml`: GitHub Actions workflow that on every push/PR runs `ruff check .`, `mypy .`, and `pytest`, using a Postgres + Redis service container so tests that touch the DB can run in CI.

6. `tests/test_health.py`: integration test hitting `/health` with httpx's `AsyncClient`, asserting 200 and the expected response shape.

Definition of done: `docker compose up --build` brings up all four services and `/health` returns 200. `ruff check .`, `mypy .`, `pytest` all pass locally and in the CI workflow file (I'll verify the CI run once pushed). Do not add business logic, event schemas, or collectors — that's the other track's scope this week.

When done, commit with `feat: project skeleton, docker compose, CI` and summarize any assumptions you made (env var names, port numbers, etc.) so I can reconcile them with the other track.
