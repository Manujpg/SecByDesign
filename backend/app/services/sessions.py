"""Serverseitige Sitzungen (SR-07, ADR A5).

- Token: 256 Bit Zufall, nur der SHA-256-Hash liegt in der Datenbank. Ein DB-Leak
  liefert damit keine verwendbaren Sitzungen.
- Ablauf: Leerlauf-Timeout und absolutes Limit; bei offener MFA-Prüfung nur wenige Minuten.
- Widerruf: Logout löscht die Sitzung; Passwortwechsel löscht alle Sitzungen des Kontos.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import (
    hash_token,
    hash_user_agent,
    is_plausible_session_token,
    new_session_token,
)
from app.core.timeutil import as_utc, utcnow
from app.models import User, UserSession

# Schreiblast begrenzen: last_seen_at höchstens einmal pro Minute aktualisieren.
_TOUCH_INTERVAL = timedelta(seconds=60)


@dataclass(frozen=True)
class IssuedSession:
    token: str
    session: UserSession
    max_age_seconds: int


def create_session(
    db: Session,
    user: User,
    *,
    mfa_verified: bool,
    ip: str | None,
    user_agent: str | None,
) -> IssuedSession:
    settings = get_settings()
    now = utcnow()
    if user.mfa_enabled and not mfa_verified:
        lifetime = timedelta(minutes=settings.mfa_pending_minutes)
    else:
        lifetime = timedelta(hours=settings.session_absolute_hours)
    token = new_session_token()
    record = UserSession(
        user_id=user.id,
        token_hash=hash_token(token),
        created_at=now,
        last_seen_at=now,
        expires_at=now + lifetime,
        mfa_verified=mfa_verified,
        ip=(ip or None) and ip[:45],
        user_agent_hash=hash_user_agent(user_agent),
    )
    db.add(record)
    db.flush()
    return IssuedSession(token=token, session=record, max_age_seconds=int(lifetime.total_seconds()))


def resolve_session(db: Session, token: str | None) -> tuple[UserSession, User] | None:
    """Liefert Sitzung und Konto zu einem Cookie-Token oder ``None``, wenn ungültig."""
    if token is None or not is_plausible_session_token(token):
        return None
    row = db.execute(
        select(UserSession, User)
        .join(User, User.id == UserSession.user_id)
        .where(UserSession.token_hash == hash_token(token))
    ).first()
    if row is None:
        return None
    session, user = row
    now = utcnow()
    idle_limit = timedelta(minutes=get_settings().session_idle_minutes)
    expired = as_utc(session.expires_at) <= now or as_utc(session.last_seen_at) + idle_limit <= now
    if expired or not user.is_active:
        # Sofort festschreiben: der Request endet gleich mit 401 und würde sonst
        # zurückgerollt, die abgelaufene Sitzung bliebe in der Datenbank liegen.
        db.delete(session)
        db.commit()
        return None
    if now - as_utc(session.last_seen_at) >= _TOUCH_INTERVAL:
        session.last_seen_at = now
    return session, user


def revoke_session(db: Session, session: UserSession) -> None:
    db.delete(session)
    db.flush()


def revoke_all_sessions(db: Session, user_id: uuid.UUID) -> None:
    db.execute(delete(UserSession).where(UserSession.user_id == user_id))
    db.flush()
