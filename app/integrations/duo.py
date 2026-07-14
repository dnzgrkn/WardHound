"""Async Cisco Duo Admin API verification-push client."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import format_datetime
from typing import Any, cast
from urllib.parse import quote, urlencode

import httpx

DUO_TIMEOUT_SECONDS = 10.0
DUO_CONFIRMATION_ATTEMPTS = 10
DUO_CONFIRMATION_INTERVAL_SECONDS = 1.0


class DuoError(RuntimeError):
    """Raised when Duo cannot complete and confirm a verification push."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True)
class DuoVerificationResult:
    """Safe audit details for a confirmed Duo verification challenge."""

    verification_confirmed: bool = True


class DuoClient:
    """Resolve a Duo user, send a verification push, and confirm approval."""

    def __init__(
        self,
        api_hostname: str,
        integration_key: str,
        secret_key: str,
        *,
        timeout: float = DUO_TIMEOUT_SECONDS,
        transport: httpx.AsyncBaseTransport | None = None,
        date_factory: Callable[[], str] | None = None,
        confirmation_attempts: int = DUO_CONFIRMATION_ATTEMPTS,
        confirmation_interval: float = DUO_CONFIRMATION_INTERVAL_SECONDS,
    ) -> None:
        hostname = api_hostname.strip().lower()
        if (
            not hostname
            or "/" in hostname
            or ":" in hostname
            or not hostname.endswith(".duosecurity.com")
        ):
            raise ValueError("Duo API hostname must be a duosecurity.com hostname")
        if confirmation_attempts < 1 or confirmation_interval < 0:
            raise ValueError("Duo confirmation polling settings are invalid")
        self._hostname = hostname
        self._integration_key = integration_key
        self._secret_key = secret_key
        self._date_factory = date_factory or _http_date
        self._confirmation_attempts = confirmation_attempts
        self._confirmation_interval = confirmation_interval
        self._client = httpx.AsyncClient(
            base_url=f"https://{hostname}", timeout=timeout, transport=transport
        )

    async def __aenter__(self) -> DuoClient:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self._client.aclose()

    async def require_verification(self, username: str) -> DuoVerificationResult:
        """Send and confirm an immediate verification push for one active Duo user."""
        user = await self._lookup_user(username)
        user_id = _required_string(user, "user_id", "Duo user")
        phone_id = _push_phone_id(user)
        push = cast(
            dict[str, Any],
            await self._api_request(
                "POST",
                f"/admin/v1/users/{user_id}/send_verification_push",
                {"phone_id": phone_id},
                operation="verification push",
            ),
        )
        push_id = _required_string(push, "push_id", "Duo verification push")

        result = await self._confirm_push(user_id, push_id)
        if result != "approve":
            raise DuoError(f"Duo verification push was not approved (result: {result})")

        confirmed_user = cast(
            dict[str, Any],
            await self._api_request(
                "GET",
                f"/admin/v1/users/{user_id}",
                {},
                operation="user confirmation",
            ),
        )
        if (
            confirmed_user.get("user_id") != user_id
            or confirmed_user.get("username") != username
            or confirmed_user.get("status") != "active"
            or confirmed_user.get("is_enrolled") is not True
        ):
            raise DuoError("Duo confirmation read did not show the expected active user")
        return DuoVerificationResult()

    async def _lookup_user(self, username: str) -> dict[str, Any]:
        response = cast(
            list[Any],
            await self._api_request(
                "GET",
                "/admin/v1/users",
                {"username": username},
                operation="user lookup",
                expect_list=True,
            ),
        )
        if len(response) != 1:
            raise DuoError("Duo user was not found")
        user = response[0]
        if not isinstance(user, dict) or user.get("username") != username:
            raise DuoError("Duo user lookup returned an unexpected identity")
        if user.get("status") != "active" or user.get("is_enrolled") is not True:
            raise DuoError("Duo user is not active and enrolled")
        return user

    async def _confirm_push(self, user_id: str, push_id: str) -> str:
        for attempt in range(self._confirmation_attempts):
            response = cast(
                dict[str, Any],
                await self._api_request(
                    "GET",
                    f"/admin/v1/users/{user_id}/verification_push_response",
                    {"push_id": push_id},
                    operation="verification confirmation",
                ),
            )
            result = response.get("result")
            if result != "waiting":
                if not isinstance(result, str):
                    raise DuoError("Duo verification response omitted its result")
                return result
            if attempt + 1 < self._confirmation_attempts:
                await asyncio.sleep(self._confirmation_interval)
        raise DuoError("Duo verification push confirmation timed out")

    async def _api_request(
        self,
        method: str,
        path: str,
        params: Mapping[str, str],
        *,
        operation: str,
        expect_list: bool = False,
    ) -> dict[str, Any] | list[Any]:
        encoded = _canonical_params(params)
        date = self._date_factory()
        authorization = _authorization_header(
            self._integration_key,
            self._secret_key,
            date,
            method,
            self._hostname,
            path,
            encoded,
        )
        kwargs: dict[str, Any] = {"headers": {"Date": date, "Authorization": authorization}}
        if method == "GET":
            kwargs["params"] = encoded
        else:
            kwargs["content"] = encoded
            kwargs["headers"]["Content-Type"] = "application/x-www-form-urlencoded"
        try:
            response = await self._client.request(method, path, **kwargs)
        except httpx.TimeoutException as exc:
            raise DuoError("Duo request timed out") from exc
        except httpx.RequestError as exc:
            raise DuoError("Duo request could not connect") from exc
        if not response.is_success:
            raise DuoError(
                f"Duo {operation} returned HTTP {response.status_code}",
                status_code=response.status_code,
            )
        try:
            envelope: Any = response.json()
        except ValueError as exc:
            raise DuoError(f"Duo {operation} response was not valid JSON") from exc
        if not isinstance(envelope, dict) or envelope.get("stat") != "OK":
            raise DuoError(f"Duo {operation} response was not successful")
        payload = envelope.get("response")
        expected_type = list if expect_list else dict
        if not isinstance(payload, expected_type):
            raise DuoError(f"Duo {operation} response had an invalid payload")
        return payload


def _http_date() -> str:
    return format_datetime(datetime.now(UTC), usegmt=True)


def _canonical_params(params: Mapping[str, str]) -> str:
    return urlencode(sorted(params.items()), quote_via=quote, safe="~")


def _authorization_header(
    integration_key: str,
    secret_key: str,
    date: str,
    method: str,
    hostname: str,
    path: str,
    encoded_params: str,
) -> str:
    canonical = "\n".join((date, method.upper(), hostname.lower(), path, encoded_params))
    signature = hmac.new(
        secret_key.encode("utf-8"), canonical.encode("ascii"), hashlib.sha1
    ).hexdigest()
    credentials = base64.b64encode(f"{integration_key}:{signature}".encode("ascii")).decode("ascii")
    return f"Basic {credentials}"


def _required_string(payload: Mapping[str, Any], key: str, label: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise DuoError(f"{label} omitted {key}")
    return value


def _push_phone_id(user: Mapping[str, Any]) -> str:
    phones = user.get("phones")
    if not isinstance(phones, list):
        raise DuoError("Duo user phone list was invalid")
    for phone in phones:
        if not isinstance(phone, dict) or phone.get("activated") is not True:
            continue
        capabilities = phone.get("capabilities")
        phone_id = phone.get("phone_id")
        if (
            isinstance(capabilities, list)
            and "push" in capabilities
            and isinstance(phone_id, str)
            and phone_id
        ):
            return phone_id
    raise DuoError("Duo user has no activated push-capable phone")
