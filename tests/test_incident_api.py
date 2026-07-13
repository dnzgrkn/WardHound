from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.realtime import IncidentConnectionManager
from app.api.services import ApiServices, get_api_services
from app.engines.analysis import AnalysisConfigurationError
from app.engines.response import InMemoryApprovalStore, ResponseEngine
from app.main import create_app
from app.schemas.analysis import Evidence, RootCauseAnalysis
from app.schemas.events import (
    EntityType,
    NormalizedEntity,
    NormalizedEvent,
    NormalizedEventType,
    Severity,
    SourceSystem,
)
from app.schemas.incidents import Incident
from app.stores.incidents import InMemoryEventStore, InMemoryIncidentStore

API_KEY = "synthetic-dashboard-key"
HEADERS = {"X-API-Key": API_KEY}


class StaticAnalysisEngine:
    async def analyze(
        self, incident: Incident, evidence: Sequence[NormalizedEvent]
    ) -> RootCauseAnalysis:
        return RootCauseAnalysis(
            probable_cause="Synthetic cross-system access chain.",
            confidence=0.87,
            evidence=[
                Evidence(
                    event_id=evidence[0].id,
                    description="A synthetic authentication failure started the chain.",
                )
            ],
            recommended_actions=[],
            side_effects="An operator may need to verify expected administrative activity.",
        )


def api_services() -> ApiServices:
    return ApiServices(
        incidents=InMemoryIncidentStore(),
        events=InMemoryEventStore(),
        response_engine=ResponseEngine(InMemoryApprovalStore()),
        analysis_engine_factory=StaticAnalysisEngine,
        connections=IncidentConnectionManager(),
    )


@pytest.fixture
def application(monkeypatch: pytest.MonkeyPatch) -> FastAPI:
    monkeypatch.setenv("WARDHOUND_API_KEY", API_KEY)
    app = create_app()
    services = api_services()
    app.dependency_overrides[get_api_services] = lambda: services
    return app


def correlated_events() -> list[NormalizedEvent]:
    start = datetime(2026, 7, 13, 9, tzinfo=UTC)
    user = NormalizedEntity(entity_type=EntityType.USER, username="jdoe", domain="CORP")
    device = NormalizedEntity(
        entity_type=EntityType.DEVICE,
        mac_address="aa:bb:cc:dd:ee:ff",
        hostname="WKSTN-0042",
    )
    target = NormalizedEntity(entity_type=EntityType.DEVICE, hostname="SRV-T0-0042")
    return [
        NormalizedEvent(
            raw_event_id=uuid4(),
            source_system=SourceSystem.ACTIVE_DIRECTORY,
            event_type=NormalizedEventType.AUTH_FAILED,
            severity=Severity.MEDIUM,
            primary_entity=user,
            occurred_at=start,
        ),
        NormalizedEvent(
            raw_event_id=uuid4(),
            source_system=SourceSystem.PACKETFENCE,
            event_type=NormalizedEventType.DEVICE_QUARANTINED,
            severity=Severity.HIGH,
            primary_entity=device,
            related_entities=[user],
            occurred_at=start + timedelta(minutes=4),
        ),
        NormalizedEvent(
            raw_event_id=uuid4(),
            source_system=SourceSystem.JUMPSERVER,
            event_type=NormalizedEventType.SESSION_STARTED,
            severity=Severity.MEDIUM,
            primary_entity=user,
            related_entities=[target],
            occurred_at=start + timedelta(minutes=8),
            extra_attributes={"id": "session-synthetic-0042", "remote_addr": "10.20.30.40"},
        ),
    ]


def event_payload() -> dict[str, object]:
    return {"events": [event.model_dump(mode="json") for event in correlated_events()]}


def ingest_one_incident(client: TestClient) -> UUID:
    response = client.post("/api/v1/events", headers=HEADERS, json=event_payload())
    assert response.status_code == 200
    incidents = response.json()
    assert len(incidents) == 1
    return UUID(incidents[0]["id"])


def test_correlation_spans_separate_ingestion_requests(application: FastAPI) -> None:
    """A rule's events split across requests must still correlate into one incident.

    Real collectors post events as they occur, not as one bulk batch — this is a regression
    test for ingest_events() correlating against services.events.get_all() (all retained
    evidence) rather than only the events attached to the current request.
    """
    events = correlated_events()
    with TestClient(application) as client:
        first = client.post(
            "/api/v1/events",
            headers=HEADERS,
            json={"events": [event.model_dump(mode="json") for event in events[:2]]},
        )
        assert first.status_code == 200
        assert first.json() == []

        second = client.post(
            "/api/v1/events",
            headers=HEADERS,
            json={"events": [event.model_dump(mode="json") for event in events[2:]]},
        )

    assert second.status_code == 200
    incidents = second.json()
    assert len(incidents) == 1
    assert {event.id for event in events} == {
        UUID(event_id) for event_id in incidents[0]["event_ids"]
    }


def test_api_key_is_required(application: FastAPI) -> None:
    with TestClient(application) as client:
        response = client.get("/api/v1/incidents")

    assert response.status_code == 401


def test_posting_events_creates_listable_incident(application: FastAPI) -> None:
    with TestClient(application) as client:
        incident_id = ingest_one_incident(client)
        response = client.get(
            "/api/v1/incidents",
            headers=HEADERS,
            params={"severity": "critical", "status": "open", "sort_by": "risk_score"},
        )

    assert response.status_code == 200
    assert [UUID(item["id"]) for item in response.json()] == [incident_id]


def test_incident_detail_contains_evidence_and_saved_analysis(application: FastAPI) -> None:
    with TestClient(application) as client:
        incident_id = ingest_one_incident(client)
        analysis_response = client.post(
            f"/api/v1/incidents/{incident_id}/analyze",
            headers=HEADERS,
        )
        detail_response = client.get(
            f"/api/v1/incidents/{incident_id}",
            headers=HEADERS,
        )

    assert analysis_response.status_code == 200
    assert detail_response.status_code == 200
    detail = detail_response.json()
    assert len(detail["evidence"]) == 3
    assert detail["analysis"]["confidence"] == 0.87


def test_analysis_configuration_error_has_typed_response(
    application: FastAPI,
) -> None:
    services = api_services()

    def unavailable_analysis_engine() -> StaticAnalysisEngine:
        raise AnalysisConfigurationError("Synthetic analysis provider is not configured")

    services = ApiServices(
        incidents=services.incidents,
        events=services.events,
        response_engine=services.response_engine,
        analysis_engine_factory=unavailable_analysis_engine,
        connections=services.connections,
    )
    application.dependency_overrides[get_api_services] = lambda: services

    with TestClient(application) as client:
        incident_id = ingest_one_incident(client)
        response = client.post(
            f"/api/v1/incidents/{incident_id}/analyze",
            headers=HEADERS,
        )

    assert response.status_code == 503
    assert response.json()["code"] == "analysis_not_configured"


def test_action_approve_reject_and_error_mapping(application: FastAPI) -> None:
    quarantine_action = {
        "action_type": "quarantine_device",
        "rationale": "Contain the synthetic endpoint while an operator reviews evidence.",
        "requires_approval": True,
    }
    disable_action = {
        "action_type": "disable_user",
        "rationale": "Suspend the synthetic account pending operator review.",
        "requires_approval": True,
    }
    with TestClient(application) as client:
        incident_id = ingest_one_incident(client)
        requested = client.post(
            f"/api/v1/incidents/{incident_id}/actions",
            headers=HEADERS,
            json=quarantine_action,
        )
        record_id = UUID(requested.json()["id"])
        approved = client.post(
            f"/api/v1/actions/{record_id}/approve",
            headers=HEADERS,
            json={"decided_by": "analyst-01"},
        )
        conflict = client.post(
            f"/api/v1/actions/{record_id}/approve",
            headers=HEADERS,
            json={"decided_by": "analyst-01"},
        )
        missing = client.post(
            f"/api/v1/actions/{uuid4()}/approve",
            headers=HEADERS,
            json={"decided_by": "analyst-01"},
        )
        second_request = client.post(
            f"/api/v1/incidents/{incident_id}/actions",
            headers=HEADERS,
            json=disable_action,
        )
        rejected = client.post(
            f"/api/v1/actions/{second_request.json()['id']}/reject",
            headers=HEADERS,
            json={"decided_by": "analyst-01", "reason": "Expected synthetic activity."},
        )

    assert requested.status_code == 200
    assert requested.json()["approval_status"] == "pending"
    assert approved.status_code == 200
    assert approved.json()["execution_status"] == "simulated"
    assert conflict.status_code == 409
    assert conflict.json()["code"] == "invalid_action_transition"
    assert missing.status_code == 404
    assert missing.json()["code"] == "action_not_found"
    assert rejected.status_code == 200
    assert rejected.json()["approval_status"] == "rejected"
    assert rejected.json()["execution_status"] == "not_executed"


def test_incident_actions_list_returns_latest_snapshots(application: FastAPI) -> None:
    action = {
        "action_type": "quarantine_device",
        "rationale": "Contain the synthetic endpoint while an operator reviews evidence.",
        "requires_approval": True,
    }
    second_action = {
        "action_type": "disable_user",
        "rationale": "Suspend the synthetic account pending operator review.",
        "requires_approval": True,
    }
    with TestClient(application) as client:
        missing = client.get(
            f"/api/v1/incidents/{uuid4()}/actions",
            headers=HEADERS,
        )
        incident_id = ingest_one_incident(client)
        empty = client.get(
            f"/api/v1/incidents/{incident_id}/actions",
            headers=HEADERS,
        )
        requested = client.post(
            f"/api/v1/incidents/{incident_id}/actions",
            headers=HEADERS,
            json=action,
        )
        record_id = requested.json()["id"]
        pending = client.get(
            f"/api/v1/incidents/{incident_id}/actions",
            headers=HEADERS,
        )
        client.post(
            f"/api/v1/actions/{record_id}/approve",
            headers=HEADERS,
            json={"decided_by": "analyst-01"},
        )
        approved = client.get(
            f"/api/v1/incidents/{incident_id}/actions",
            headers=HEADERS,
        )
        second_requested = client.post(
            f"/api/v1/incidents/{incident_id}/actions",
            headers=HEADERS,
            json=second_action,
        )
        second_record_id = second_requested.json()["id"]
        client.post(
            f"/api/v1/actions/{second_record_id}/reject",
            headers=HEADERS,
            json={"decided_by": "analyst-01", "reason": "Expected synthetic activity."},
        )
        final = client.get(
            f"/api/v1/incidents/{incident_id}/actions",
            headers=HEADERS,
        )

    assert missing.status_code == 404
    assert missing.json()["code"] == "incident_not_found"
    assert empty.status_code == 200
    assert empty.json() == []
    assert pending.json()[0]["approval_status"] == "pending"
    assert approved.status_code == 200
    assert len(approved.json()) == 1
    assert approved.json()[0]["id"] == record_id
    assert approved.json()[0]["approval_status"] == "approved"
    assert approved.json()[0]["execution_status"] == "simulated"
    records_by_id = {record["id"]: record for record in final.json()}
    assert records_by_id[record_id]["approval_status"] == "approved"
    assert records_by_id[second_record_id]["approval_status"] == "rejected"
    assert records_by_id[second_record_id]["execution_status"] == "not_executed"


def test_websocket_broadcasts_incident_creation(application: FastAPI) -> None:
    with (
        TestClient(application) as client,
        client.websocket_connect(f"/api/v1/ws/incidents?api_key={API_KEY}") as websocket,
    ):
        response = client.post(
            "/api/v1/events",
            headers=HEADERS,
            json=event_payload(),
        )
        message = websocket.receive_json()

    assert response.status_code == 200
    assert message["type"] == "incident_created"
    assert message["payload"]["id"] == response.json()[0]["id"]


def test_websocket_broadcasts_completed_analysis(application: FastAPI) -> None:
    with (
        TestClient(application) as client,
        client.websocket_connect(f"/api/v1/ws/incidents?api_key={API_KEY}") as websocket,
    ):
        incident_id = ingest_one_incident(client)
        websocket.receive_json()
        response = client.post(
            f"/api/v1/incidents/{incident_id}/analyze",
            headers=HEADERS,
        )
        message = websocket.receive_json()

    assert response.status_code == 200
    assert message["type"] == "analysis_completed"
    assert UUID(message["payload"]["incident_id"]) == incident_id
    assert message["payload"]["analysis"] == response.json()
