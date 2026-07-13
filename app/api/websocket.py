"""Authenticated realtime incident WebSocket endpoint."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect, status

from app.api.auth import api_key_matches, configured_api_key
from app.api.services import ApiServicesDependency

router = APIRouter(prefix="/api/v1", tags=["incidents"])


@router.websocket("/ws/incidents")
async def incident_updates(
    websocket: WebSocket,
    services: ApiServicesDependency,
    api_key: Annotated[str | None, Query()] = None,
) -> None:
    """Keep a browser-compatible authenticated connection for typed dashboard updates."""
    if configured_api_key() is None:
        await websocket.close(code=status.WS_1011_INTERNAL_ERROR)
        return
    if not api_key_matches(api_key):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    await services.connections.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        services.connections.disconnect(websocket)
