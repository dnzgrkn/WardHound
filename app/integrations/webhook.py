"""Async client for low-risk administrator webhook notifications."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

import httpx

WEBHOOK_TIMEOUT_SECONDS = 10.0
MAX_RATIONALE_LENGTH = 500


class WebhookError(RuntimeError):
    """Raised when a webhook notification cannot be delivered."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class WebhookClient:
    """Send one bounded, Slack-compatible administrator notification."""

    def __init__(
        self,
        webhook_url: str,
        *,
        timeout: float = WEBHOOK_TIMEOUT_SECONDS,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._client = httpx.AsyncClient(timeout=timeout, transport=transport)
        self._webhook_url = webhook_url

    async def __aenter__(self) -> WebhookClient:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self._client.aclose()

    async def send_notification(
        self,
        incident_id: UUID | None,
        severity: str,
        rationale: str,
        timestamp: datetime,
    ) -> int:
        """POST only the fields an administrator needs for initial triage."""
        payload = _slack_compatible_payload(incident_id, severity, rationale, timestamp)
        try:
            response = await self._client.post(self._webhook_url, json=payload)
        except httpx.TimeoutException as exc:
            raise WebhookError("Administrator notification webhook timed out") from exc
        except httpx.RequestError as exc:
            raise WebhookError("Administrator notification webhook could not connect") from exc
        except httpx.InvalidURL as exc:
            raise WebhookError("Administrator notification webhook URL is invalid") from exc

        if not response.is_success:
            raise WebhookError(
                f"Administrator notification webhook returned HTTP {response.status_code}",
                status_code=response.status_code,
            )
        return response.status_code


def _slack_compatible_payload(
    incident_id: UUID | None,
    severity: str,
    rationale: str,
    timestamp: datetime,
) -> dict[str, str]:
    incident_label = str(incident_id) if incident_id is not None else "unlinked"
    normalized_rationale = " ".join(rationale.split())[:MAX_RATIONALE_LENGTH]
    text = (
        "WardHound administrator notification\n"
        f"Incident: {incident_label}\n"
        f"Severity: {severity}\n"
        f"Summary: {normalized_rationale}\n"
        f"Timestamp: {timestamp.isoformat()}"
    )
    return {"text": text}
