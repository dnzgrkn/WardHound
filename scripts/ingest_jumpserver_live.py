"""Pull real recent activity from a live JumpServer instance into WardHound.

This is a one-shot bridge script, not a background service: it polls JumpServer's
login-logs, sessions, and commands endpoints for a time window (via the existing,
already-tested ``JumpServerCollector.poll()``), then POSTs whatever normalized
events it finds to WardHound's own ``/api/v1/events`` ingestion endpoint so they
run through the real correlation/risk/policy pipeline exactly like any other
collector-sourced event.

Authentication: this instance enforces MFA org-wide on every interactive login
(``POST /api/v1/authentication/auth/``), with no per-account override. JumpServer's
answer to "a script can't do an interactive MFA challenge" is AccessKey auth —
an ID + Secret pair (Personal Settings > Access key) used to HMAC-sign each
request directly, bypassing the login/MFA flow entirely because it never goes
through it. This is the documented, intended mechanism for headless automation
against an MFA-enforced JumpServer, not a workaround: nothing about the org's
MFA policy changes, no account's protection is weakened. Algorithm is the
"Signing HTTP Messages" scheme JumpServer's own drf-httpsig backend implements
(HMAC-SHA256 over "(request-target)", "accept", "date", "host").

This is intentionally separate from JUMPSERVER_API_TOKEN in .env.example, which
belongs to the already-reviewed SOAR write-path integration
(app/integrations/jumpserver.py) and is not touched by this script.

Configuration is read from environment variables:

    JUMPSERVER_BASE_URL         e.g. http://192.168.110.25  (lab-local address only)
    JUMPSERVER_ACCESS_KEY_ID    from Personal Settings > Access key > Create
    JUMPSERVER_ACCESS_KEY_SECRET  shown once at creation time — save it then
    WARDHOUND_API_URL           default: http://localhost:8000
    WARDHOUND_API_KEY           the same static key docker-compose already uses

Usage:
    python scripts/ingest_jumpserver_live.py --since-hours 24
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import hmac
import os
import re
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from email.utils import formatdate
from pathlib import Path

import httpx
from dotenv import load_dotenv

from app.collectors.jumpserver import _LOGIN_DATETIME_FORMAT, JumpServerCollector
from app.schemas.events import NormalizedEvent

# Load WardHound/.env regardless of the shell's current directory, so these
# credentials only need to be set once instead of re-typed into every new
# PowerShell tab. Real values (JUMPSERVER_ACCESS_KEY_ID/SECRET etc.) belong
# only in .env, which is gitignored -- .env.example stays a placeholder template.
load_dotenv(Path(__file__).resolve().parent.parent / ".env")


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"Missing required environment variable: {name}")
    return value


async def _fetch_records_tolerant(
    client: httpx.AsyncClient, url: str, params: dict[str, str]
) -> list[dict[str, object]]:
    """Fetch every page from a JumpServer list endpoint.

    app/collectors/jumpserver.py's own _fetch_records() requires a DRF-style
    paginated envelope ({"results": [...], "next": ...}), which is what that
    collector was verified against. This JumpServer instance returns a bare
    JSON array for these endpoints instead (confirmed via a direct probe
    request), so this script uses a tolerant variant that accepts either shape.
    Everything downstream (parse_raw/normalize) is unchanged and reused as-is.
    """
    response = await client.get(url, params=params)
    response.raise_for_status()
    body = response.json()
    if isinstance(body, list):
        if not all(isinstance(item, dict) for item in body):
            raise ValueError(f"JumpServer {url} list response must contain objects")
        return body
    if isinstance(body, dict) and isinstance(body.get("results"), list):
        records = list(body["results"])
        next_url = body.get("next")
        if isinstance(next_url, str) and next_url:
            records.extend(await _fetch_records_tolerant(client, next_url, {}))
        return records
    raise ValueError(f"Unrecognized JumpServer response shape from {url}: {body!r:.200}")


def _slash_datetime_to_iso(value: object) -> object:
    """Convert this instance's 'YYYY/MM/DD HH:MM:SS +ZZZZ' fields to ISO 8601.

    app/collectors/jumpserver.py's _normalize_session() expects session date_start/
    date_end as ISO 8601 (per the API shape it was verified against). This instance
    returns the same slash-separated format everywhere, including session
    timestamps (confirmed via a real ValueError from the reviewed parser) — so this
    script converts just those two fields before handing records to the untouched,
    reviewed normalize() logic.
    """
    if not isinstance(value, str):
        return value
    try:
        return datetime.strptime(value, _LOGIN_DATETIME_FORMAT).isoformat()
    except ValueError:
        return value


_DISPLAY_NAME_USER = re.compile(r"^.*\(([^()]+)\)\s*$")


def _session_username_to_bare(value: object) -> object:
    """Strip this instance's 'Display Name(username)' session user field to a bare username.

    app/collectors/jumpserver.py's _normalize_session() uses payload["user"] verbatim
    as the entity username. This instance's login-logs endpoint already returns a bare
    username, but its sessions endpoint returns "Display Name(username)" (e.g.
    "someuser(someuser)", "Administrator(admin)") for the same field name -- confirmed
    by comparing real auth_succeeded vs session_started output for the same real login.
    Left as-is downstream, this breaks CrossSystemCompromiseRule's username-based entity
    matching against the bare usernames AD and PacketFence report. Extracting just the
    parenthesized part restores a consistent identity key across all three sources.
    """
    if not isinstance(value, str):
        return value
    match = _DISPLAY_NAME_USER.match(value)
    return match.group(1) if match else value


async def _poll_tolerant(
    collector: JumpServerCollector, client: httpx.AsyncClient, since: datetime
) -> list[NormalizedEvent]:
    """Same three JumpServer resources as JumpServerCollector.poll(), tolerant fetch."""
    login_since = since.strftime(_LOGIN_DATETIME_FORMAT)
    session_since = since.astimezone(UTC).isoformat().replace("+00:00", "Z")
    command_since = str(int(since.timestamp()))

    login_records = await _fetch_records_tolerant(
        client, collector.login_url, {"date_from": login_since}
    )
    session_records = await _fetch_records_tolerant(
        client, collector.sessions_url, {"date_start_from": session_since}
    )
    command_records = await _fetch_records_tolerant(
        client, collector.commands_url, {"timestamp_from": command_since}
    )

    events = [collector.process({**record, "kind": "login"}) for record in login_records]
    # One-shot pull, no prior poll state to diff against: emit each session's
    # current state (started or ended) exactly once, unlike the long-running
    # poll() which tracks transitions across repeated calls.
    for record in session_records:
        adapted = {
            **record,
            "kind": "session",
            "date_start": _slash_datetime_to_iso(record.get("date_start")),
            "date_end": _slash_datetime_to_iso(record.get("date_end")),
            "user": _session_username_to_bare(record.get("user")),
        }
        events.append(collector.process(adapted))
    events.extend(collector.process({**record, "kind": "command"}) for record in command_records)
    return events


class JumpServerAccessKeyAuth(httpx.Auth):
    """HMAC-SHA256 request signing for JumpServer's AccessKey auth (drf-httpsig).

    Signs "(request-target)", "accept", "date", and "host" for every request,
    matching JumpServer's own documented Python example (httpsig.requests_auth.
    HTTPSignatureAuth with algorithm="hmac-sha256" and the same header set).
    """

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
            self.secret.encode("utf-8"), signing_string.encode("utf-8"), hashlib.sha256
        ).digest()
        signature = base64.b64encode(digest).decode("ascii")
        request.headers["Date"] = date
        request.headers["Host"] = host
        request.headers["Authorization"] = (
            f'Signature keyId="{self.key_id}",algorithm="hmac-sha256",'
            f'headers="(request-target) accept date host",signature="{signature}"'
        )
        yield request


async def main(since_hours: float) -> None:
    jumpserver_base_url = _require_env("JUMPSERVER_BASE_URL")
    access_key_id = _require_env("JUMPSERVER_ACCESS_KEY_ID")
    access_key_secret = _require_env("JUMPSERVER_ACCESS_KEY_SECRET")
    wardhound_api_url = os.environ.get("WARDHOUND_API_URL", "http://localhost:8000")
    wardhound_api_key = _require_env("WARDHOUND_API_KEY")

    since = datetime.now(UTC) - timedelta(hours=since_hours)
    print(f"Polling JumpServer for activity since {since.isoformat()} ...")

    collector = JumpServerCollector()
    async with httpx.AsyncClient(
        base_url=jumpserver_base_url,
        headers={"Accept": "application/json"},
        auth=JumpServerAccessKeyAuth(access_key_id, access_key_secret),
        timeout=30.0,
    ) as jumpserver_client:
        try:
            events: list[NormalizedEvent] = await _poll_tolerant(
                collector, jumpserver_client, since
            )
        except httpx.HTTPStatusError as exc:
            print(f"JumpServer request failed ({exc.response.status_code}): {exc.response.text}")
            raise

    if not events:
        print("No new JumpServer activity found in that window. Nothing to ingest.")
        return

    print(f"Found {len(events)} normalized event(s):")
    for event in events:
        entities = [event.primary_entity, *event.related_entities]
        entity_desc = ", ".join(
            f"user={e.username!r}" if e.username else f"mac={e.mac_address!r}" if e.mac_address
            else f"host={e.hostname!r}" if e.hostname else "?"
            for e in entities
        )
        print(
            f"  - {event.event_type.value} ({event.severity.value}) "
            f"at {event.occurred_at} [{entity_desc}]"
        )

    async with httpx.AsyncClient(
        base_url=wardhound_api_url,
        headers={"X-API-Key": wardhound_api_key},
        timeout=30.0,
    ) as wardhound_client:
        response = await wardhound_client.post(
            "/api/v1/events",
            json={"events": [event.model_dump(mode="json") for event in events]},
        )
        response.raise_for_status()
        incidents = response.json()

    print(f"Ingested. WardHound returned {len(incidents)} incident(s) after correlation.")
    for incident in incidents:
        print(f"  - [{incident['severity']}] {incident['title']} (risk {incident['risk_score']})")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--since-hours",
        type=float,
        default=24.0,
        help="How far back to poll JumpServer for activity (default: 24 hours)",
    )
    args = parser.parse_args()
    asyncio.run(main(args.since_hours))
