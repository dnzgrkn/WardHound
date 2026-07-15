from __future__ import annotations

import pytest

from app.config.secrets import EnvSecretProvider


async def test_env_secret_provider_reads_current_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = EnvSecretProvider()
    monkeypatch.delenv("WARDHOUND_SYNTHETIC_SECRET", raising=False)

    assert await provider.get("WARDHOUND_SYNTHETIC_SECRET") is None

    monkeypatch.setenv("WARDHOUND_SYNTHETIC_SECRET", " synthetic-value ")

    assert await provider.get("WARDHOUND_SYNTHETIC_SECRET") == " synthetic-value "
