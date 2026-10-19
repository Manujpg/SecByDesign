"""Gemeinsame Test-Fixtures.

Die Tests laufen ohne PostgreSQL gegen eine In-Memory-SQLite-Datenbank. Die
Umgebungsvariablen werden gesetzt, bevor die App importiert wird.
"""

from __future__ import annotations

import os

os.environ["APP_ENV"] = "test"
os.environ["DATABASE_URL"] = "sqlite+pysqlite:///:memory:"
os.environ.setdefault("LOG_LEVEL", "WARNING")

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import get_db
from app.main import create_app
from app.models import Base


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


@pytest.fixture
def client(app) -> TestClient:
    # raise_server_exceptions=False: wir wollen die echte 500-Antwort sehen.
    return TestClient(app, raise_server_exceptions=False)
