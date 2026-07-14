"""Async Cisco Secure Firewall Management Center blocklist client."""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
from typing import Any
from urllib.parse import urlsplit

import httpx

FMC_TIMEOUT_SECONDS = 10.0


class FirepowerError(RuntimeError):
    """Raised when FMC cannot confirm a requested blocklist mutation."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True)
class BlockIpResult:
    """Safe audit details for confirmed FMC network-group membership."""

    already_blocked: bool
    enforcement_pending_deploy: bool = True


class FirepowerClient:
    """Add an IP literal to one pre-provisioned FMC Network Group."""

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        *,
        timeout: float = FMC_TIMEOUT_SECONDS,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        parsed_url = urlsplit(base_url)
        if parsed_url.scheme.casefold() != "https" or parsed_url.hostname is None:
            raise ValueError("FMC base URL must use https://")
        self._username = username
        self._password = password
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            timeout=timeout,
            transport=transport,
        )

    async def __aenter__(self) -> FirepowerClient:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self._client.aclose()

    async def add_blocklist_member(
        self, network_group_id: str, target_ip: str
    ) -> BlockIpResult:
        """Ensure an IP Host literal is present and confirm the stored FMC object."""
        canonical_ip = str(ip_address(target_ip))
        token, domain_uuid = await self._authenticate()
        path = (
            f"/api/fmc_config/v1/domain/{domain_uuid}/object/networkgroups/"
            f"{network_group_id}"
        )
        headers = {"X-auth-access-token": token, "Accept": "application/json"}
        group = await self._get_group(path, headers)
        _validate_network_group(group, network_group_id)
        literals = _literals(group)
        already_blocked = _contains_host_literal(literals, canonical_ip)

        if not already_blocked:
            update = _network_group_update(group, literals, canonical_ip)
            response = await self._request("PUT", path, headers=headers, json=update)
            if not response.is_success:
                raise FirepowerError(
                    f"FMC network-group update returned HTTP {response.status_code}",
                    status_code=response.status_code,
                )
            confirmed_group = await self._get_group(path, headers)
            _validate_network_group(confirmed_group, network_group_id)
            if not _contains_host_literal(_literals(confirmed_group), canonical_ip):
                raise FirepowerError(
                    "FMC confirmation read did not show the IP in the blocklist"
                )

        return BlockIpResult(already_blocked=already_blocked)

    async def _authenticate(self) -> tuple[str, str]:
        response = await self._request(
            "POST",
            "/api/fmc_platform/v1/auth/generatetoken",
            auth=httpx.BasicAuth(self._username, self._password),
        )
        if not response.is_success:
            raise FirepowerError(
                f"FMC token generation returned HTTP {response.status_code}",
                status_code=response.status_code,
            )
        token = response.headers.get("X-auth-access-token", "").strip()
        domain_uuid = response.headers.get("DOMAIN_UUID", "").strip()
        if not token or not domain_uuid:
            raise FirepowerError("FMC token response omitted required authentication headers")
        return token, domain_uuid

    async def _get_group(self, path: str, headers: dict[str, str]) -> dict[str, Any]:
        response = await self._request("GET", path, headers=headers)
        if response.status_code == 404:
            raise FirepowerError("FMC blocklist Network Group was not found", status_code=404)
        if not response.is_success:
            raise FirepowerError(
                f"FMC network-group read returned HTTP {response.status_code}",
                status_code=response.status_code,
            )
        try:
            payload: Any = response.json()
        except ValueError as exc:
            raise FirepowerError("FMC network-group response was not valid JSON") from exc
        if not isinstance(payload, dict):
            raise FirepowerError("FMC network-group response was not an object")
        return payload

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        try:
            return await self._client.request(method, path, **kwargs)
        except httpx.TimeoutException as exc:
            raise FirepowerError("FMC request timed out") from exc
        except httpx.RequestError as exc:
            raise FirepowerError("FMC request could not connect") from exc


def _literals(group: dict[str, Any]) -> list[dict[str, Any]]:
    literals = group.get("literals", [])
    if not isinstance(literals, list) or not all(
        isinstance(literal, dict) for literal in literals
    ):
        raise FirepowerError("FMC Network Group literals were invalid")
    return [dict(literal) for literal in literals]


def _validate_network_group(group: dict[str, Any], expected_id: str) -> None:
    if group.get("id") != expected_id or group.get("type") != "NetworkGroup":
        raise FirepowerError("FMC Network Group identity was invalid")
    if not isinstance(group.get("name"), str) or not group["name"]:
        raise FirepowerError("FMC Network Group omitted its name")


def _contains_host_literal(literals: list[dict[str, Any]], target_ip: str) -> bool:
    for literal in literals:
        if literal.get("type") != "Host" or not isinstance(literal.get("value"), str):
            continue
        try:
            if str(ip_address(literal["value"])) == target_ip:
                return True
        except ValueError:
            continue
    return False


def _network_group_update(
    group: dict[str, Any], literals: list[dict[str, Any]], target_ip: str
) -> dict[str, Any]:
    objects = group.get("objects", [])
    if not isinstance(objects, list):
        raise FirepowerError("FMC Network Group objects were invalid")
    update: dict[str, Any] = {
        "id": group["id"],
        "name": group["name"],
        "type": group["type"],
        "objects": objects,
        "literals": [*literals, {"type": "Host", "value": target_ip}],
    }
    for key in ("description", "overridable"):
        if key in group:
            update[key] = group[key]
    return update
