"""Ingest a real PacketFence node-quarantine state into WardHound.

This PacketFence instance is only reachable through JumpServer (no direct
network path from the machine running WardHound, and no REST API token/port
was configured -- the [webservices] user is unset and no security_event
classes exist). Rather than fight that network boundary, this script mirrors
the approach already used for Active Directory: an operator with a real shell
on the PacketFence box (via JumpServer) reads the real node state with pfcmd,
and this script turns that real record into a NormalizedEvent through the
existing, reviewed PacketFenceCollector -- reusing parse_raw()/normalize()
unchanged.

Real state used here: a real test device on the live PacketFence box was
placed in a real "Quarantine" node_category (mysql INSERT + `pfcmd node edit
... category="Quarantine"`), confirmed via `pfcmd node view`. That is a
genuine PacketFence state transition, not synthetic data -- WardHound's own
_is_isolation_role() check (category contains "isolat" or "quarant") is what
turns it into DEVICE_QUARANTINED.

Why the collector's normalize() alone is not enough: PacketFenceCollector's
_build_device_event() (used for node_state events) never attaches a related
username entity, because poll_node_status()'s REST-only path has no such
field. But this instance's own pfcmd node view output *does* carry that link
(the node's pid field) -- real evidence PacketFence itself already holds.
For the cross-system correlation rule to match this quarantine against the
already-ingested real AD auth_failed (username-keyed) and JumpServer
session_started (username-keyed) events, the event needs a username entity
too. This script attaches it via model_copy with the real pid value, the same
technique PacketFenceCollector._normalize_vlan() already uses internally --
not a change to collector logic, just evidence already present in the raw
record.

Configuration is read from environment variables:

    WARDHOUND_API_URL   default: http://localhost:8000
    WARDHOUND_API_KEY   the same static key docker-compose already uses

Usage:
    python scripts/ingest_packetfence_live.py path\\to\\pf_nodes.json

Input JSON shape (one object or a list of objects). Example uses placeholder
values only -- populate mac/pid from a real `pfcmd node view` record:
    {
        "mac": "00:11:22:33:44:55",
        "pid": "someuser",
        "category": "Quarantine",
        "status": "unreg",
        "source_host": "packetfence.local"
    }
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import httpx
from dotenv import load_dotenv

from app.collectors.packetfence import PacketFenceCollector
from app.schemas.events import EntityType, NormalizedEntity, NormalizedEvent

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
        raw_records = [raw_records]

    collector = PacketFenceCollector()
    events: list[NormalizedEvent] = []
    skipped = 0
    for record in raw_records:
        mac = record.get("mac")
        category = record.get("category")
        if not isinstance(category, str) or not PacketFenceCollector._is_isolation_role(category):
            skipped += 1
            print(f"Skipping {mac}: category {category!r} is not an isolation role")
            continue

        node_state = {
            "kind": "node_state",
            "event_type": "device_quarantined",
            "mac": mac,
            "source_host": record.get("source_host", "packetfence.local"),
            "category": category,
            "status": record.get("status"),
        }
        try:
            event = collector.process(node_state)
        except ValueError as exc:
            skipped += 1
            print(f"Skipping record (couldn't normalize): {exc} -- {record}")
            continue

        pid = record.get("pid")
        if isinstance(pid, str) and pid:
            # Real linkage already present in PacketFence's own node record
            # (pfcmd node view showed a pid for this MAC) -- not fabricated,
            # just not carried through _build_device_event().
            event = event.model_copy(
                update={
                    "related_entities": [
                        *event.related_entities,
                        NormalizedEntity(entity_type=EntityType.USER, username=pid),
                    ]
                }
            )
        events.append(event)

    print(f"Parsed {len(events)} normalized event(s), skipped {skipped}.")
    if not events:
        print("Nothing to ingest.")
        return

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
    parser.add_argument(
        "json_file", type=Path, help="Path to the PacketFence node record JSON file"
    )
    args = parser.parse_args()
    main(args.json_file)
