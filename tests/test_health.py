"""Integration tests for the health endpoint."""

import pytest
from httpx import ASGITransport, AsyncClient

from app.api.health import check_database, check_redis
from app.main import create_app


async def dependency_available() -> bool:
    """Represent an available external dependency in endpoint tests."""
    return True


@pytest.mark.asyncio
async def test_health_returns_connected_services() -> None:
    application = create_app()
    application.dependency_overrides[check_database] = dependency_available
    application.dependency_overrides[check_redis] = dependency_available

    async with AsyncClient(
        transport=ASGITransport(app=application), base_url="http://test"
    ) as client:
        response = await client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "healthy",
        "database": "connected",
        "redis": "connected",
    }

