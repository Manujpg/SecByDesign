"""Einstiegspunkt der FastAPI-Anwendung."""

from __future__ import annotations

from fastapi import FastAPI

from app.api import health
from app.api.v1 import api_router
from app.core.config import Settings, get_settings
from app.core.errors import register_exception_handlers
from app.core.logging import configure_logging
from app.core.middleware import RequestContextMiddleware


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)

    # OpenAPI und Swagger-UI nur in der Entwicklung: im Cluster keine Endpunkt-Enumeration.
    docs_enabled = settings.is_dev
    app = FastAPI(
        title="PraxisTermin API",
        docs_url="/docs" if docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json" if docs_enabled else None,
        swagger_ui_oauth2_redirect_url=None,
    )

    register_exception_handlers(app)
    app.add_middleware(RequestContextMiddleware)

    app.include_router(health.router)
    app.include_router(api_router, prefix="/api/v1")
    return app


app = create_app()
