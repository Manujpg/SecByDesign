"""Audit-Logging (SR-11).

Grundsätze:
- append-only: die Laufzeit-Rolle darf in ``audit_log`` nur INSERT/SELECT,
- keine Passwörter, Tokens, Freitexte oder Gesundheitsdaten,
- Login-Versuche werden mit einer HMAC-Kennung der E-Mail statt der E-Mail selbst protokolliert.

Das Audit-Log dient zugleich als Datenquelle für das Rate-Limiting (siehe ``count_recent``),
damit keine zweite, manipulierbare Zählertabelle nötig ist.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.logging import request_id_ctx
from app.core.timeutil import as_utc, utcnow
from app.models import AuditLog, AuditOutcome

logger = logging.getLogger("app.audit")


class Action:
    """Stabile Aktionsnamen (werden im Audit-Log gespeichert)."""

    LOGIN = "auth.login"
    LOGOUT = "auth.logout"
    REGISTER = "auth.register"
    CREDENTIAL_CHANGE = "auth.password_change"
    ACCOUNT_LOCKED = "auth.account_locked"
    RATE_LIMITED = "auth.rate_limited"
    ADMIN_BOOTSTRAP = "system.admin_bootstrap"
    MFA_SETUP = "auth.mfa_setup"
    MFA_ENABLE = "auth.mfa_enable"
    MFA_VERIFY = "auth.mfa_verify"
    MFA_RECOVERY_USED = "auth.mfa_recovery_used"
    MFA_RECOVERY_REGENERATE = "auth.mfa_recovery_regenerate"
    MFA_DISABLE = "auth.mfa_disable"


def record(
    db: Session,
    action: str,
    outcome: AuditOutcome,
    *,
    actor_id: uuid.UUID | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    ip: str | None = None,
) -> None:
    db.add(
        AuditLog(
            ts=utcnow(),
            action=action,
            outcome=outcome,
            actor_id=actor_id,
            target_type=target_type,
            target_id=target_id,
            request_id=request_id_ctx.get(),
            ip=(ip or None) and ip[:45],
        )
    )
    # Zusätzlich ins strukturierte Log, damit Ereignisse auch ohne DB-Zugriff sichtbar sind.
    logger.info(
        "audit",
        extra={"event": f"audit:{action}:{outcome.value}"},
    )


def count_recent(
    db: Session,
    action: str,
    outcome: AuditOutcome,
    *,
    window: timedelta,
    ip: str | None = None,
    target_id: str | None = None,
    actor_id: uuid.UUID | None = None,
    since: datetime | None = None,
) -> int:
    start = utcnow() - window
    if since is not None and as_utc(since) > start:
        start = as_utc(since)
    stmt = (
        select(func.count())
        .select_from(AuditLog)
        .where(
            AuditLog.action == action,
            AuditLog.outcome == outcome,
            AuditLog.ts >= start,
        )
    )
    if ip is not None:
        stmt = stmt.where(AuditLog.ip == ip)
    if target_id is not None:
        stmt = stmt.where(AuditLog.target_id == target_id)
    if actor_id is not None:
        stmt = stmt.where(AuditLog.actor_id == actor_id)
    return int(db.scalar(stmt) or 0)


def last_event_ts(
    db: Session, action: str, outcome: AuditOutcome, *, target_id: str
) -> datetime | None:
    ts = db.scalar(
        select(func.max(AuditLog.ts)).where(
            AuditLog.action == action,
            AuditLog.outcome == outcome,
            AuditLog.target_id == target_id,
        )
    )
    return as_utc(ts) if ts is not None else None
