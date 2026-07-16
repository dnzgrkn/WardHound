"""Ingest exported Active Directory Security event log records into WardHound.

Windows doesn't expose Security event log entries over a REST API, and
app/collectors/active_directory.py's ActiveDirectoryCollector.normalize()
requires each event pre-rendered as named fields (TargetUserName,
TargetDomainName, TimeCreated, IpAddress, ...) — per its own docstring,
these only exist in the event's XML rendering, not Format-List or raw
.Properties output. scripts/export-ad-security-events.ps1 does that XML
extraction on the domain controller and writes a JSON file; this script reads
that file and POSTs the normalized events to WardHound's ingestion endpoint,
reusing the existing, reviewed collector's parse_raw()/normalize() unchanged.

Configuration is read from environment variables:

    WARDHOUND_API_URL   default: http://localhost:8000
    WARDHOUND_API_KEY   the same static key docker-compose already uses

Usage:
    python scripts/ingest_ad_events.py path\\to\\ad_events.json
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import httpx
from dotenv import load_dotenv

from app.collectors.active_directory import ActiveDirectoryCollector
from app.schemas.events import NormalizedEvent

# Load WardHound/.env regardless of the shell's current directory, so these
# credentials only need to be set once instead of re-typed into every new
# PowerShell tab. Real values belong only in .env, which is gitignored.
load_dotenv(Path(__file__).resolve().parent.parent / ".env")


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"Missing required environment variable: {name}")
    return value


def main(json_path: Path) -> None:
    wardhound_api_url = os.environ.get("WARDHOUND_API_URL", "http://localhost:8000")
    wardhound_api_key = _require_env("WARDHOUND_API_KEY")

    raw_records = json.loads(json_path.read_text(encoding="utf-8-sig"))
    if isinstance(raw_records, dict):
        # PowerShell's ConvertTo-Json collapses a one-item array to a bare
        # object unless the exporter script explicitly wraps with @(...),
        # which it does — this branch is just defense in depth.
        raw_records = [raw_records]

    collector = ActiveDirectoryCollector()
    events: list[NormalizedEvent] = []
    skipped = 0
    for record in raw_records:
        cleaned = {key: value for key, value in record.items() if value is not None}
        try:
            events.append(collector.process(cleaned))
        except ValueError as exc:
            skipped += 1
            print(f"Skipping record (couldn't normalize): {exc} -- {cleaned}")

    print(f"Parsed {len(events)} normalized event(s), skipped {skipped}.")
    if not events:
        print("Nothing to ingest.")
        return

    for event in events:
        print(f"  - {event.event_type.value} ({event.severity.value}) at {event.occurred_at}")

    with httpx.Client(
        base_url=wardhound_api_url,
        headers={"X-API-Key": wardhound_api_key},
        timeout=30.0,
    ) as client:
        response = client.post(
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
    parser.add_argument("json_file", type=Path, help="Path to the exported AD events JSON file")
    args = parser.parse_args()
    main(args.json_file)
