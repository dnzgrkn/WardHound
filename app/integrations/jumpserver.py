"""Async JumpServer privileged-session termination client."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

JUMPSERVER_TIMEOUT_SECONDS = 10.0


class JumpServerError(RuntimeError):
    """Raised when JumpServer cannot confirm a requested session termination."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True)
class TerminateSessionResult:
    """Safe audit details for a confirmed finished JumpServer session."""

    termination_confirmed: bool = True


class JumpServerClient:
    """Queue JumpServer's kill-session task and confirm resulting session state."""

    def __init__(
        self,
        base_url: str,
        api_token: str,
        *,
        timeout: float = JUMPSERVER_TIMEOUT_SECONDS,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        parsed_url = urlsplit(base_url)
        if parsed_url.scheme.casefold() != "https" or parsed_url.hostname is None:
            raise ValueError("JumpServer base URL must use https://")
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            headers={
                "Authorization": f"Token {api_token}",
                "Accept": "application/json",
            },
            timeout=timeout,
            transport=transport,
        )

    async def __aenter__(self) -> JumpServerClient:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self._client.aclose()

    async def terminate_session(self, session_id: str) -> TerminateSessionResult:
        """Queue one kill task and confirm the session becomes finished."""
        response = await self._request(
            "POST", "/api/v1/terminal/tasks/kill-session/", json=[session_id]
        )
        if not response.is_success:
            raise JumpServerError(
                f"JumpServer session termination returned HTTP {response.status_code}",
                status_code=response.status_code,
            )
        payload = self._json_object(response, "termination")
        accepted = payload.get("ok")
        if not isinstance(accepted, list) or session_id not in accepted:
            raise JumpServerError("JumpServer did not accept the session termination task")

        session_response = await self._request(
            "GET", f"/api/v1/terminal/sessions/{session_id}/"
        )
        if session_response.status_code == 404:
            raise JumpServerError("JumpServer session was not found", status_code=404)
        if not session_response.is_success:
            raise JumpServerError(
                f"JumpServer session confirmation returned HTTP {session_response.status_code}",
                status_code=session_response.status_code,
            )
        session = self._json_object(session_response, "session confirmation")
        if session.get("id") != session_id or session.get("is_finished") is not True:
            raise JumpServerError(
                "JumpServer confirmation read did not show the session as finished"
            )
        return TerminateSessionResult()

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        try:
            return await self._client.request(method, path, **kwargs)
        except httpx.TimeoutException as exc:
            raise JumpServerError("JumpServer request timed out") from exc
        except httpx.RequestError as exc:
            raise JumpServerError("JumpServer request could not connect") from exc

    @staticmethod
    def _json_object(response: httpx.Response, operation: str) -> dict[str, Any]:
        try:
            payload: Any = response.json()
        except ValueError as exc:
            raise JumpServerError(
                f"JumpServer {operation} response was not valid JSON"
            ) from exc
        if not isinstance(payload, dict):
            raise JumpServerError(f"JumpServer {operation} response was not an object")
        return payload
