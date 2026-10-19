"""Gemeinsame Test-Fixtures.

Die Tests laufen ohne PostgreSQL gegen eine In-Memory-SQLite-Datenbank. Die
Umgebungsvariablen werden gesetzt, bevor die App importiert wird.
"""

from __future__ import annotations

import os

# Lokale backend/.env darf Tests nicht beeinflussen.
os.environ["SETTINGS_ENV_FILE"] = ""
os.environ["APP_ENV"] = "test"
os.environ["DATABASE_URL"] = "sqlite+pysqlite:///:memory:"
os.environ.setdefault("LOG_LEVEL", "WARNING")
os.environ["ALLOWED_ORIGINS"] = "https://testserver"
# Schnelles Argon2 nur für Tests; Produktion nutzt die Werte aus der Architektur.
os.environ["ARGON2_TIME_COST"] = "1"
os.environ["ARGON2_MEMORY_COST_KIB"] = "1024"
os.environ["ARGON2_PARALLELISM"] = "1"

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import get_db
from app.main import create_app
from app.models import Base

ORIGIN = "https://testserver"


@pytest.fixture
def engine():
    eng = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(eng, "connect")
    def _fk_on(dbapi_conn, _):  # SQLite prüft Fremdschlüssel nur auf Anfrage
        dbapi_conn.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture
def db(engine) -> Iterator[Session]:
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    yield session
    session.close()


@pytest.fixture
def app(engine):
    application = create_app()
    factory = sessionmaker(bind=engine, expire_on_commit=False)

    def _get_db() -> Iterator[Session]:
        session = factory()
        try:
            yield session
            session.commit()
        finally:
            session.close()

    application.dependency_overrides[get_db] = _get_db
    return application


def make_client(app) -> TestClient:
    # HTTPS-Basis-URL, sonst sendet der Client das Secure-Cookie nicht zurück.
    # raise_server_exceptions=False: wir wollen die echte 500-Antwort sehen.
    return TestClient(
        app, base_url=ORIGIN, headers={"Origin": ORIGIN}, raise_server_exceptions=False
    )


@pytest.fixture
def client(app) -> TestClient:
    return make_client(app)


@pytest.fixture
def settings():
    from app.core.config import get_settings

    return get_settings()
