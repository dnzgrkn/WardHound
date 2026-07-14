"""Prometheus HTTP and business metrics with bounded-cardinality labels."""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

HTTP_REQUESTS = Counter(
    "wardhound_http_requests_total",
    "API requests completed.",
    ("method", "route", "status_code"),
)
HTTP_DURATION = Histogram(
    "wardhound_http_request_duration_seconds",
    "API request latency.",
    ("method", "route"),
)
INCIDENTS_CREATED = Counter(
    "wardhound_incidents_created_total", "New incidents retained.", ("severity",)
)
RESPONSE_ACTIONS = Counter(
    "wardhound_response_actions_total",
    "Response action lifecycle transitions.",
    ("action_type", "transition"),
)
AI_ANALYSIS_CALLS = Counter(
    "wardhound_ai_analysis_calls_total", "AI analysis calls.", ("result",)
)
AI_ANALYSIS_DURATION = Histogram(
    "wardhound_ai_analysis_duration_seconds", "AI analysis call latency."
)


def instrument_metrics(app: FastAPI) -> None:
    """Expose Prometheus metrics and record every HTTP request."""

    @app.get("/metrics", include_in_schema=False)
    async def metrics() -> Response:
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    @app.middleware("http")
    async def record_http_metrics(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        started = time.perf_counter()
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        finally:
            route = request.scope.get("route")
            route_path = getattr(route, "path", "unmatched")
            HTTP_REQUESTS.labels(request.method, route_path, str(status_code)).inc()
            HTTP_DURATION.labels(request.method, route_path).observe(
                time.perf_counter() - started
            )
