# Week 1 — Track A (Claude Code): Event contracts + ADRs

Run this in its own worktree/branch: `git worktree add ../wardhound-schemas feat/event-schemas`, then `cd` into it and start Claude Code there.

---

**Prompt to paste into Claude Code:**

We're bootstrapping WardHound (read CLAUDE.md and docs/SPEC.md first — that's the full context, don't ask me to repeat it). This is Week 1, Track A. A second agent (Codex) is working in parallel in a different worktree on branch `feat/project-skeleton`, building the Docker Compose / FastAPI app shell / CI. Do not touch those files — stay in the scope below.

Your scope for this session:

1. Design and implement the core event contracts in `app/schemas/events.py` using Pydantic v2:
   - `RawEvent`: source system (enum: `packetfence`, `jumpserver`, `active_directory`, `firewall`), raw payload (dict or str), received_at timestamp, source_host.
   - `NormalizedEvent`: everything a downstream correlation/risk/AI layer needs — entity (user/device/IP), event_type (a normalized enum spanning all four source systems' event types listed in docs/SPEC.md), severity, source system, original RawEvent reference, normalized_at timestamp. Think carefully about what "entity" means across a user-centric AD event vs a device-centric PacketFence event vs an IP-centric firewall event — this schema is the contract every later engine depends on, so don't under-design it.
   - Write these as the module every collector, the correlation engine, and the AI layer will import. Get the naming right now; changing it later is expensive.

2. Implement `app/collectors/base.py`: an abstract base class `BaseCollector` that every real collector (PacketFence syslog, JumpServer API poller, AD event reader, firewall syslog) will subclass. Define the interface: how a collector receives raw input and returns a `RawEvent`, plus a `normalize()` hook or a separate normalizer interface — your call, but write an ADR explaining the choice (see below).

3. Write ADR 0002 in `docs/adr/0002-event-schema-and-collector-interface.md` covering: why this shape for `NormalizedEvent` (especially the entity-modeling decision), why collectors are structured the way they are, and what happens when a new source system needs onboarding (extensibility story).

4. Write unit tests in `tests/test_schemas.py` and `tests/test_collectors.py` covering the schema validation rules and the base collector contract (use a fake/dummy collector subclass for the test).

5. Run `ruff check .` and `mypy .` and `pytest` before you're done — all must pass.

Do not build actual PacketFence/JumpServer/AD/firewall collectors yet — that's Week 2. This session is only the contracts and the base interface.

When done, commit with `feat: event schemas and collector base interface` (small logical commits are fine too) and tell me what naming/design decisions you made so I can sanity-check them against what I'm seeing in the real PacketFence/JumpServer/AD logs at the internship.
