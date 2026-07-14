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
    node_status: str | None


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

    async def isolate_node(self, mac_address: str) -> PacketFenceIsolationResult:
        """Deregister one node so PacketFence moves it to isolated access."""
        try:
            response = await self._client.post(
                "/api/v1/nodes/bulk_deregister",
                json={"items": [mac_address]},
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

        return PacketFenceIsolationResult(
            status_code=response.status_code,
            node_status=_node_status(response, mac_address),
        )


def _node_status(response: httpx.Response, mac_address: str) -> str | None:
    try:
        payload: Any = response.json()
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    items = payload.get("items")
    if not isinstance(items, list):
        return None
    for item in items:
        if not isinstance(item, dict):
            continue
        item_mac = item.get("mac")
        status = item.get("status")
        if (
            isinstance(item_mac, str)
            and item_mac.casefold() == mac_address.casefold()
            and isinstance(status, str)
        ):
            return status
    return None
