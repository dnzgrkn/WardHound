from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest

from app.digest_delivery import SUMMARY_LIMIT, DigestDeliveryClient, DigestDeliverySettings
from app.schemas.digest import AggregateStat, DailyDigest, DigestNarrative
from app.schemas.events import EntityType, NormalizedEntity, Severity
from app.schemas.incidents import Incident


def _digest() -> DailyDigest:
    start = datetime(2026, 7, 16, 12, tzinfo=UTC)
    sensitive_marker = "SYNTHETIC-ENTITY-MUST-NOT-LEAK"
    incident = Incident(
        title="Synthetic retained incident",
        summary=f"Raw evidence marker {sensitive_marker}",
        event_ids=[uuid4()],
        entities=[NormalizedEntity(entity_type=EntityType.USER, username=sensitive_marker)],
        severity=Severity.HIGH,
        risk_score=70,
        created_at=start,
        correlation_rule_id="synthetic_delivery_rule",
    )
    return DailyDigest(
        period_start=start,
        period_end=start + timedelta(days=1),
        incidents=[incident],
        aggregate_stats=[
            AggregateStat(name="incidents_by_severity", label="high", count=1),
            AggregateStat(name="incidents_by_severity", label="critical", count=0),
        ],
        narrative=DigestNarrative(
            executive_summary=f"Synthetic bounded summary about {sensitive_marker}. " + "x" * 700,
            highlights=[],
            recommended_follow_up=[],
        ),
    )


@pytest.mark.parametrize(
    ("url", "enabled", "configured"),
    [
        ("", "false", False),
        ("https://hooks.example.com/services/synthetic-token", "false", False),
        ("", "true", False),
        ("https://hooks.example.com/services/synthetic-token", "true", True),
    ],
)
def test_delivery_requires_both_configuration_signals(
    monkeypatch: pytest.MonkeyPatch, url: str, enabled: str, configured: bool
) -> None:
    monkeypatch.setenv("DIGEST_DELIVERY_WEBHOOK_URL", url)
    monkeypatch.setenv("DIGEST_DELIVERY_REAL_EXECUTION", enabled)
    assert (DigestDeliverySettings.from_env() is not None) is configured


async def test_delivery_payload_is_bounded_and_excludes_evidence_entities_and_credentials() -> None:
    webhook_url = "https://hooks.example.com/services/synthetic-token"
    captured = b""

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal captured
        captured = request.content
        return httpx.Response(204)

    settings = DigestDeliverySettings(webhook_url, "https://wardhound.example.com")
    status_code = await DigestDeliveryClient(
        settings, transport=httpx.MockTransport(handler)
    ).deliver(_digest())

    payload = json.loads(captured)
    text = payload["text"]
    assert status_code == 204
    assert set(payload) == {"text"}
    assert "SYNTHETIC-ENTITY-MUST-NOT-LEAK" not in text
    assert webhook_url not in text
    assert "synthetic-token" not in text
    summary = text.split("Executive summary: ", 1)[1].split("\nPDF:", 1)[0]
    assert len(summary) <= SUMMARY_LIMIT
