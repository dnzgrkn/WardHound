"""OpenTelemetry setup and named spans for operationally important work."""

from __future__ import annotations

import os

from fastapi import FastAPI
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

tracer = trace.get_tracer("wardhound.api")
_configured = False


def instrument_tracing(app: FastAPI) -> None:
    """Instrument FastAPI and export spans over OTLP when enabled."""
    global _configured
    disabled = os.getenv("OTEL_SDK_DISABLED", "false").casefold() == "true"
    if not disabled and not _configured:
        provider = TracerProvider(resource=Resource.create({"service.name": "wardhound-api"}))
        endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
        provider.add_span_processor(
            BatchSpanProcessor(OTLPSpanExporter(endpoint=f"{endpoint.rstrip('/')}/v1/traces"))
        )
        trace.set_tracer_provider(provider)
        _configured = True
    FastAPIInstrumentor.instrument_app(app)
