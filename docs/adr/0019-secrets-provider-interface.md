# ADR 0019: Async secrets-provider interface

- Status: Accepted
- Date: 2026-07-15

## Context

The seven real-execution handlers read their connection settings, credentials, secret webhook
URLs, and independent execution flags directly with `os.getenv`. Environment variables are the
correct current deployment mechanism, but inline access permanently couples response policy to
that one source and makes a later remote secrets backend require another cross-cutting handler
rewrite.

There is no selected or deployed Vault, AWS Secrets Manager, or equivalent backend to integrate
with today. Choosing one now would add authentication, availability, deployment, and dependency
costs without a real infrastructure target or operational requirements. That would be premature in
the same way that implementing multi-tenant machinery before a concrete tenancy model would be.

## Decision

`app.config.secrets` defines a deliberately small boundary:

```python
class SecretProvider(Protocol):
    async def get(self, key: str) -> str | None: ...
```

The method is asynchronous from its first version because a future remote lookup is I/O. This
follows ADR 0009's corrected rule: potential-I/O ports are native async contracts rather than
sync interfaces later hidden behind threads or nested event loops.

`EnvSecretProvider` implements the current behavior by returning `os.getenv(key)`, and the
module-level `default_secret_provider` is an `EnvSecretProvider` instance typed as the protocol.
Response handlers await that object for every configuration key. Tests can replace the module-level
object with a small fake, matching the established integration-client monkeypatch pattern.

All normalization remains in the handlers exactly where it was: missing values become empty
strings, the same settings are whitespace-trimmed, passwords and secret keys retain their original
untrimmed semantics, flags still require case-normalized `true`, and every multi-signal gate keeps
the same all-or-nothing conditions. Integration clients continue receiving ordinary strings and
are unchanged.

## Deferred real-provider responsibilities

A production remote provider needs design choices that the environment implementation does not:

- backend authentication and least-privilege policy;
- credential rotation and TTL-based caching without serving values beyond their allowed lifetime;
- explicit fetch timeout, failure, retry, exponential-backoff, and fail-closed behavior;
- concurrency control so simultaneous actions do not stampede the backend;
- auditable secret-access metadata that records key names, caller, status, and timing without ever
  recording secret values; and
- availability and startup policy for cached versus unavailable credentials.

Those choices depend on the actual backend and deployment service-level objectives. This ADR does
not invent a generic cache or error policy before those requirements exist.

## Consequences

Current deployments have zero runtime configuration change: they supply the exact same environment
variables, `EnvSecretProvider` reads them at handler execution time, and every existing gate retains
its prior behavior. No dependency is added, no network call is introduced, and no integration
client changes.

The response engine now has one async seam ready for a future provider. Selecting and implementing
that provider remains a separately reviewed infrastructure stage with its own authentication,
failure, rotation, observability, and testing requirements.
