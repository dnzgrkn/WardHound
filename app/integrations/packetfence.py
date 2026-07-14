"""Async PacketFence client for explicitly enabled node isolation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

PACKETFENCE_TIMEOUT_SECONDS = 10.0


class PacketFenceError(RuntimeError):
    """Raised when PacketFence cannot confirm a requested mutation."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True)
class PacketFenceIsolationResult:
    """Safe subset of the PacketFence response retained in the audit trail."""

    status_code: int
    security_event_record_id: int


class PacketFenceClient:
    """Perform the one PacketFence write operation WardHound supports."""

    def __init__(
        self,
        base_url: str,
        api_token: str,
        *,
        timeout: float = PACKETFENCE_TIMEOUT_SECONDS,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            headers={"Accept": "application/json", "Authorization": api_token},
            timeout=timeout,
            transport=transport,
        )

    async def __aenter__(self) -> PacketFenceClient:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self._client.aclose()

    async def isolate_node(
        self, mac_address: str, security_event_id: str
    ) -> PacketFenceIsolationResult:
        """Force the configured isolation security event for one node."""
        try:
            response = await self._client.put(
                f"/api/v1/node/{mac_address}/apply_security_event",
                json={"security_event_id": security_event_id},
            )
        except httpx.TimeoutException as exc:
            raise PacketFenceError("PacketFence isolation request timed out") from exc
        except httpx.RequestError as exc:
            raise PacketFenceError("PacketFence isolation request could not connect") from exc

        if not response.is_success:
            raise PacketFenceError(
                f"PacketFence isolation request returned HTTP {response.status_code}",
                status_code=response.status_code,
            )

        record_id = _security_event_record_id(response)
        if record_id is None:
            raise PacketFenceError(
                "PacketFence isolation response did not return a security event id",
                status_code=response.status_code,
            )
        return PacketFenceIsolationResult(response.status_code, record_id)


def _security_event_record_id(response: httpx.Response) -> int | None:
    try:
        payload: Any = response.json()
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    record_id = payload.get("id")
    return record_id if isinstance(record_id, int) and record_id > 0 else None
