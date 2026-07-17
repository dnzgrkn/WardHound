"""Safety-gated delivery of bounded daily digest summaries."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

import httpx

from app.schemas.digest import DailyDigest

SUMMARY_LIMIT = 500


@dataclass(frozen=True, slots=True)
class DigestDeliverySettings:
    webhook_url: str
    public_api_url: str | None

    @classmethod
    def from_env(cls) -> DigestDeliverySettings | None:
        url = os.getenv("DIGEST_DELIVERY_WEBHOOK_URL", "").strip()
        enabled = os.getenv("DIGEST_DELIVERY_REAL_EXECUTION", "").strip().lower() == "true"
        if not url or not enabled:
            return None
        public_url = os.getenv("WARDHOUND_PUBLIC_API_URL", "").strip().rstrip("/")
        return cls(url, public_url or None)


class DigestDeliveryClient:
    """Post a Slack-compatible, evidence-free digest reference."""

    def __init__(
        self,
        settings: DigestDeliverySettings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.settings = settings
        self.transport = transport

    async def deliver(self, digest: DailyDigest) -> int:
        async with httpx.AsyncClient(timeout=10.0, transport=self.transport) as client:
            response = await client.post(
                self.settings.webhook_url,
                json={"text": _delivery_text(digest, self.settings.public_api_url)},
            )
            response.raise_for_status()
            return response.status_code


def _delivery_text(digest: DailyDigest, public_api_url: str | None) -> str:
    summary = digest.narrative.executive_summary if digest.narrative else "Not available"
    summary = " ".join(summary.split())[:SUMMARY_LIMIT]
    for incident in digest.incidents:
        for entity in incident.entities:
            summary = re.sub(
                re.escape(entity.display_name), "[redacted]", summary, flags=re.IGNORECASE
            )
    severity_counts = {
        stat.label: stat.count
        for stat in digest.aggregate_stats
        if stat.name == "incidents_by_severity"
    }
    pdf_reference = (
        f"{public_api_url}/api/v1/digests/{digest.id}/pdf"
        if public_api_url
        else f"API digest {digest.id} (PDF available from the authenticated digest endpoint)"
    )
    return (
        "WardHound daily security digest\n"
        f"Digest: {digest.id}\n"
        f"Period: {digest.period_start.isoformat()} to {digest.period_end.isoformat()}\n"
        f"Incidents: {len(digest.incidents)} "
        f"(critical={severity_counts.get('critical', 0)}, high={severity_counts.get('high', 0)})\n"
        f"Executive summary: {summary}\n"
        f"PDF: {pdf_reference}"
    )
