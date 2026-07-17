"""Live JumpServer API adaptations discovered during real evidence ingestion."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from collections.abc import Generator
from datetime import datetime
from email.utils import formatdate
from typing import Any

import httpx

from app.collectors.jumpserver import _LOGIN_DATETIME_FORMAT, JumpServerCollector

_DISPLAY_NAME_USER = re.compile(r"^.*\(([^()]+)\)\s*$")


def _slash_datetime_to_iso(value: object) -> object:
    if not isinstance(value, str):
        return value
    try:
        return datetime.strptime(value, _LOGIN_DATETIME_FORMAT).isoformat()
    except ValueError:
        return value


def _session_username_to_bare(value: object) -> object:
    if not isinstance(value, str):
        return value
    match = _DISPLAY_NAME_USER.match(value)
    return match.group(1) if match else value


class LiveJumpServerCollector(JumpServerCollector):
    """Collector transport adapting the three API quirks confirmed by ADR 0021."""

    async def _fetch_records(
        self, client: httpx.AsyncClient, url: str, params: dict[str, str]
    ) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        next_url: str | None = url
        next_params: dict[str, str] | None = params
        while next_url is not None:
            response = await client.get(next_url, params=next_params)
            response.raise_for_status()
            body = response.json()
            if isinstance(body, list):
                page = body
                candidate = None
            elif isinstance(body, dict) and isinstance(body.get("results"), list):
                page = body["results"]
                candidate = body.get("next")
            else:
                raise ValueError(f"Unrecognized JumpServer response shape from {url}")
            if not all(isinstance(item, dict) for item in page):
                raise ValueError(f"JumpServer {url} list response must contain objects")
            records.extend(self._adapt_record(url, item) for item in page)
            if candidate is not None and not isinstance(candidate, str):
                raise ValueError("JumpServer API next link must be a string or null")
            next_url = candidate or None
            next_params = None
        return records

    def _adapt_record(self, url: str, record: dict[str, Any]) -> dict[str, Any]:
        if url != self.sessions_url and "/terminal/sessions/" not in url:
            return record
        return {
            **record,
            "date_start": _slash_datetime_to_iso(record.get("date_start")),
            "date_end": _slash_datetime_to_iso(record.get("date_end")),
            "user": _session_username_to_bare(record.get("user")),
        }


class JumpServerAccessKeyAuth(httpx.Auth):
    """Sign JumpServer requests with its AccessKey HMAC-SHA256 scheme."""

    def __init__(self, key_id: str, secret: str) -> None:
        self.key_id = key_id
        self.secret = secret

    def auth_flow(
        self, request: httpx.Request
    ) -> Generator[httpx.Request, httpx.Response, None]:
        accept = request.headers.get("accept", "*/*")
        date = formatdate(usegmt=True)
        host = (
            request.url.host
            if request.url.port is None
            else f"{request.url.host}:{request.url.port}"
        )
        target = request.url.raw_path.decode("ascii")
        signing_string = (
            f"(request-target): {request.method.lower()} {target}\n"
            f"accept: {accept}\n"
            f"date: {date}\n"
            f"host: {host}"
        )
        digest = hmac.new(
            self.secret.encode(), signing_string.encode(), hashlib.sha256
        ).digest()
        signature = base64.b64encode(digest).decode("ascii")
        request.headers["Date"] = date
        request.headers["Host"] = host
        request.headers["Authorization"] = (
            f'Signature keyId="{self.key_id}",algorithm="hmac-sha256",'
            f'headers="(request-target) accept date host",signature="{signature}"'
        )
        yield request
