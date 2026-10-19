"""Datenbankanbindung (SQLAlchemy 2, synchron).

Alle Zugriffe laufen über das ORM bzw. gebundene Parameter; rohe SQL-Strings mit
eingesetzten Werten sind verboten (SR-04).
"""

from __future__ import annotations

from collections.abc import Iterator
from functools import lru_cache

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings


@lru_cache
def get_engine() -> Engine:
    settings = get_settings()
    return create_engine(
        settings.sqlalchemy_url(),
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=5,
        pool_timeout=10,
        # Verbindungsfehler sollen schnell auffallen statt Requests zu blockieren.
        connect_args={"connect_timeout": 5} if settings.database_url is None else {},
    )


@lru_cache
def get_sessionmaker() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), autoflush=False, expire_on_commit=False)


def get_db() -> Iterator[Session]:
    """FastAPI-Dependency: eine Session pro Request, Rollback bei Fehlern."""
    session = get_sessionmaker()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
