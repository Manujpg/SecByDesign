"""Einstiegspunkt der FastAPI-Anwendung."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy.exc import SQLAlchemyError

from app.api import health
from app.api.v1 import api_router
from app.core.config import Settings, get_settings
from app.core.errors import register_exception_handlers
from app.core.logging import configure_logging
from app.core.middleware import RequestContextMiddleware
from app.core.origin import OriginCheckMiddleware
from app.db import get_sessionmaker
from app.services.auth import bootstrap_admin

logger = logging.getLogger("app.startup")


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    # Admin-Bootstrap: legt beim allerersten Start das Admin-Konto an (siehe services/auth.py).
    if get_settings().admin_bootstrap_password is not None:
        try:
            with get_sessionmaker()() as db:
                bootstrap_admin(db)
        except SQLAlchemyError as exc:
            # Kein Absturz: Readiness meldet die fehlende DB, der nächste Start versucht es erneut.
            logger.error("Admin-Bootstrap fehlgeschlagen: %s", type(exc).__name__)
    yield


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
        lifespan=lifespan,
    )

    register_exception_handlers(app)
    # Reihenfolge: zuletzt hinzugefügt = äußerste Schicht. RequestContext umschließt die
    # Origin-Prüfung, damit auch abgelehnte Requests Request-ID und Security-Header tragen.
    app.add_middleware(OriginCheckMiddleware, allowed_origins=settings.origin_allowlist)
    app.add_middleware(RequestContextMiddleware)

    app.include_router(health.router)
    app.include_router(api_router, prefix="/api/v1")
    return app


app = create_app()
