"""Zeit-Helfer. Alle Zeitpunkte werden in UTC und zeitzonenbewusst verarbeitet."""

from __future__ import annotations

from datetime import UTC, datetime


def utcnow() -> datetime:
    return datetime.now(UTC)


def as_utc(value: datetime) -> datetime:
    """SQLite liefert naive Zeitstempel zurück; PostgreSQL zeitzonenbewusste."""
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
