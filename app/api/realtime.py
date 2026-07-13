"""In-process WebSocket connection management for dashboard updates."""

from __future__ import annotations

from fastapi import WebSocket

from app.api.models import RealtimeMessage


class IncidentConnectionManager:
    """Track local WebSocket clients and broadcast typed update envelopes."""

    def __init__(self) -> None:
        self._connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self._connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self._connections:
            self._connections.remove(websocket)

    async def broadcast[PayloadT](self, message: RealtimeMessage[PayloadT]) -> None:
        """Send one typed message to every currently connected local client."""
        disconnected: list[WebSocket] = []
        for websocket in tuple(self._connections):
            try:
                await websocket.send_text(message.model_dump_json())
            except RuntimeError:
                disconnected.append(websocket)
        for websocket in disconnected:
            self.disconnect(websocket)
