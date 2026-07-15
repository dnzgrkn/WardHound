"""Async client for vendor-neutral external ticket creation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import UUID

import httpx

TICKETING_TIMEOUT_SECONDS = 10.0
MAX_DESCRIPTION_LENGTH = 1000


class TicketingError(RuntimeError):
    """Raised when an external ticket cannot be created and confirmed."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True)
class TicketCreationResult:
    """Safe confirmation details returned by the ticketing webhook."""

    ticket_id: str
    status_code: int


class TicketingClient:
    """Create one external tracking ticket through a deployment-owned webhook."""

    def __init__(
        self,
        webhook_url: str,
        *,
        timeout: float = TICKETING_TIMEOUT_SECONDS,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._client = httpx.AsyncClient(timeout=timeout, transport=transport)
        self._webhook_url = webhook_url

    async def __aenter__(self) -> TicketingClient:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self._client.aclose()

    async def create_ticket(
        self,
        title: str,
        description: str,
        incident_id: UUID | None,
        severity: str,
    ) -> TicketCreationResult:
        """POST a bounded tracking record and require its returned identifier."""
        payload = {
            "title": " ".join(title.split()),
            "description": " ".join(description.split())[:MAX_DESCRIPTION_LENGTH],
            "incident_id": str(incident_id) if incident_id is not None else None,
            "severity": severity,
        }
        try:
            response = await self._client.post(self._webhook_url, json=payload)
        except httpx.TimeoutException as exc:
            raise TicketingError("Ticketing webhook request timed out") from exc
        except httpx.RequestError as exc:
            raise TicketingError("Ticketing webhook request could not connect") from exc
        except httpx.InvalidURL as exc:
            raise TicketingError("Ticketing webhook URL is invalid") from exc

        if not response.is_success:
            raise TicketingError(
                f"Ticketing webhook returned HTTP {response.status_code}",
                status_code=response.status_code,
            )

        ticket_id = _ticket_id(response)
        if ticket_id is None:
            raise TicketingError(
                "Ticketing webhook response did not return a ticket identifier",
                status_code=response.status_code,
            )
        return TicketCreationResult(ticket_id=ticket_id, status_code=response.status_code)


def _ticket_id(response: httpx.Response) -> str | None:
    try:
        payload: Any = response.json()
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    ticket_id = payload.get("ticket_id")
    if not isinstance(ticket_id, str) or not ticket_id.strip():
        return None
    return ticket_id.strip()
