"""Registrierung, Anmeldung, Passwortwechsel und Admin-Bootstrap (SR-01, SR-07, SR-08, SR-11).

Schutz vor Konto-Enumeration:
- Anmeldung: Für unbekannte E-Mails wird ein Dummy-Hash verifiziert (gleiche Rechenzeit),
  die Fehlermeldung ist immer identisch.
- Sperre: Das Fehlversuchs-Limit gilt pro E-Mail-Kennung, egal ob das Konto existiert.
  Eine Sperrmeldung verrät daher nicht, dass es ein Konto gibt.
- Registrierung: Bei bereits vergebener E-Mail kommt dieselbe Antwort wie bei Erfolg
  (siehe ``register_patient``).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import date, timedelta

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import AppError
from app.core.security import (
    WeakPasswordError,
    check_password_policy,
    hash_password,
    login_identifier,
    password_needs_rehash,
    verify_password,
)
from app.core.timeutil import as_utc, utcnow
from app.models import AuditOutcome, InsuranceType, Patient, Role, User
from app.services import audit
from app.services.audit import Action
from app.services.sessions import IssuedSession, create_session, revoke_all_sessions

logger = logging.getLogger("app.auth")

_WEAK_PASSWORD_MESSAGES = {
    "too_short": "Das Passwort muss mindestens 12 Zeichen lang sein.",
    "too_long": "Das Passwort darf höchstens 128 Zeichen lang sein.",
    "contains_personal_data": "Das Passwort darf keine persönlichen Angaben enthalten.",
    "too_weak": "Das Passwort ist zu leicht zu erraten. Bitte wählen Sie ein längeres "
    "oder weniger vorhersehbares Passwort.",
    "same_as_old": "Das neue Passwort muss sich vom bisherigen unterscheiden.",
}


def _invalid_credentials() -> AppError:
    return AppError(401, "invalid_credentials", "E-Mail oder Passwort ungültig.")


def _too_many_requests(window_minutes: int) -> AppError:
    return AppError(
        429,
        "too_many_attempts",
        "Zu viele Versuche. Bitte warten Sie einige Minuten und versuchen Sie es erneut.",
        headers={"Retry-After": str(window_minutes * 60)},
    )


def _weak_password(reason: str) -> AppError:
    return AppError(
        422, f"weak_password.{reason}", _WEAK_PASSWORD_MESSAGES.get(reason, "Passwort ungültig.")
    )


def normalize_email(email: str) -> str:
    return email.strip().lower()


# ---------------------------------------------------------------------------
# Registrierung
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PatientRegistration:
    email: str
    password: str
    first_name: str
    last_name: str
    birth_date: date
    phone: str | None
    insurance_type: InsuranceType


def register_patient(db: Session, data: PatientRegistration, *, ip: str | None) -> None:
    """Legt ein Patientenkonto an. Selbstregistrierung erzeugt immer die Rolle PATIENT.

    Ist die E-Mail schon vergeben, wird das bewusst nicht verraten: Die Antwort ist
    identisch, nur das Audit-Log vermerkt den Fehlschlag. (Ohne E-Mail-Versand gibt es
    keinen sicheren Weg, die Inhaberin der Adresse zu informieren, siehe Architektur Kap. 11.)
    """
    settings = get_settings()
    window = timedelta(minutes=settings.login_window_minutes)
    if (
        audit.count_recent(db, Action.REGISTER, AuditOutcome.SUCCESS, window=window, ip=ip)
        + audit.count_recent(db, Action.REGISTER, AuditOutcome.FAILURE, window=window, ip=ip)
        >= settings.register_ip_max
    ):
        audit.record(db, Action.RATE_LIMITED, AuditOutcome.FAILURE, target_type="register", ip=ip)
        db.commit()
        raise _too_many_requests(settings.login_window_minutes)

    email = normalize_email(data.email)
    try:
        check_password_policy(data.password, [email, data.first_name, data.last_name])
    except WeakPasswordError as exc:
        raise _weak_password(exc.reason) from None

    # Hash immer berechnen, auch bei vergebener E-Mail: gleiche Antwortzeit.
    password_hash = hash_password(data.password)
    exists = db.scalar(select(func.count()).select_from(User).where(User.email == email))
    if exists:
        audit.record(
            db,
            Action.REGISTER,
            AuditOutcome.FAILURE,
            target_type="login",
            target_id=login_identifier(email),
            ip=ip,
        )
        return

    user = User(email=email, password_hash=password_hash, role=Role.PATIENT)
    db.add(user)
    try:
        db.flush()
    except IntegrityError:
        # Gleichzeitige Registrierung derselben Adresse: wie "bereits vergeben" behandeln.
        db.rollback()
        audit.record(db, Action.REGISTER, AuditOutcome.FAILURE, target_type="login", ip=ip)
        return
    db.add(
        Patient(
            user_id=user.id,
            first_name=data.first_name,
            last_name=data.last_name,
            birth_date=data.birth_date,
            phone=data.phone,
            insurance_type=data.insurance_type,
        )
    )
    audit.record(
        db,
        Action.REGISTER,
        AuditOutcome.SUCCESS,
        actor_id=user.id,
        target_type="user",
        target_id=str(user.id),
        ip=ip,
    )


# ---------------------------------------------------------------------------
# Anmeldung
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LoginResult:
    user: User
    issued: IssuedSession

    @property
    def mfa_required(self) -> bool:
        return not self.issued.session.mfa_verified


def _check_rate_limits(db: Session, ident: str, user: User | None, ip: str | None) -> None:
    settings = get_settings()
    window = timedelta(minutes=settings.login_window_minutes)

    ip_failures = audit.count_recent(db, Action.LOGIN, AuditOutcome.FAILURE, window=window, ip=ip)
    if ip is not None and ip_failures >= settings.login_ip_max_failures:
        audit.record(db, Action.RATE_LIMITED, AuditOutcome.FAILURE, target_type="ip", ip=ip)
        db.commit()
        raise _too_many_requests(settings.login_window_minutes)

    # Fehlversuche seit der letzten erfolgreichen Anmeldung, pro E-Mail-Kennung.
    last_success = audit.last_event_ts(db, Action.LOGIN, AuditOutcome.SUCCESS, target_id=ident)
    ident_failures = audit.count_recent(
        db, Action.LOGIN, AuditOutcome.FAILURE, window=window, target_id=ident, since=last_success
    )
    locked = (
        user is not None and user.locked_until is not None and as_utc(user.locked_until) > utcnow()
    )
    if locked or ident_failures >= settings.login_max_failures:
        audit.record(
            db,
            Action.RATE_LIMITED,
            AuditOutcome.FAILURE,
            target_type="login",
            target_id=ident,
            ip=ip,
        )
        db.commit()
        raise _too_many_requests(settings.login_window_minutes)


def authenticate(
    db: Session, email: str, password: str, *, ip: str | None, user_agent: str | None
) -> LoginResult:
    settings = get_settings()
    email = normalize_email(email)
    ident = login_identifier(email)
    user = db.scalar(select(User).where(User.email == email))

    _check_rate_limits(db, ident, user, ip)

    password_ok = verify_password(user.password_hash if user else None, password)
    if user is None or not password_ok or not user.is_active:
        audit.record(
            db,
            Action.LOGIN,
            AuditOutcome.FAILURE,
            actor_id=user.id if user else None,
            target_type="login",
            target_id=ident,
            ip=ip,
        )
        if user is not None:
            user.failed_logins += 1
            if user.failed_logins >= settings.login_max_failures:
                user.locked_until = utcnow() + timedelta(minutes=settings.login_window_minutes)
                user.failed_logins = 0
                audit.record(
                    db,
                    Action.ACCOUNT_LOCKED,
                    AuditOutcome.SUCCESS,
                    actor_id=user.id,
                    target_type="user",
                    target_id=str(user.id),
                    ip=ip,
                )
        # Fehlversuch dauerhaft speichern, bevor der Request mit 401 endet (sonst Rollback).
        db.commit()
        raise _invalid_credentials()

    if password_needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    user.failed_logins = 0
    user.locked_until = None
    user.last_login_at = utcnow()

    issued = create_session(
        db, user, mfa_verified=not user.mfa_enabled, ip=ip, user_agent=user_agent
    )
    audit.record(
        db,
        Action.LOGIN,
        AuditOutcome.SUCCESS,
        actor_id=user.id,
        target_type="login",
        target_id=ident,
        ip=ip,
    )
    return LoginResult(user=user, issued=issued)


# ---------------------------------------------------------------------------
# Passwortwechsel
# ---------------------------------------------------------------------------


def change_password(
    db: Session,
    user: User,
    current_password: str,
    new_password: str,
    *,
    mfa_verified: bool,
    ip: str | None,
    user_agent: str | None,
) -> IssuedSession:
    if not verify_password(user.password_hash, current_password):
        audit.record(
            db,
            Action.CREDENTIAL_CHANGE,
            AuditOutcome.FAILURE,
            actor_id=user.id,
            target_type="user",
            target_id=str(user.id),
            ip=ip,
        )
        db.commit()
        raise AppError(403, "invalid_current_password", "Das aktuelle Passwort ist falsch.")
    if new_password == current_password:
        raise _weak_password("same_as_old")
    try:
        check_password_policy(new_password, [user.email])
    except WeakPasswordError as exc:
        raise _weak_password(exc.reason) from None

    user.password_hash = hash_password(new_password)
    user.password_changed_at = utcnow()
    user.must_change_password = False
    # Alle Sitzungen beenden (auch auf anderen Geräten) und eine neue ausstellen.
    revoke_all_sessions(db, user.id)
    issued = create_session(db, user, mfa_verified=mfa_verified, ip=ip, user_agent=user_agent)
    audit.record(
        db,
        Action.CREDENTIAL_CHANGE,
        AuditOutcome.SUCCESS,
        actor_id=user.id,
        target_type="user",
        target_id=str(user.id),
        ip=ip,
    )
    return issued


# ---------------------------------------------------------------------------
# Admin-Bootstrap
# ---------------------------------------------------------------------------


def bootstrap_admin(db: Session) -> bool:
    """Legt das erste Konto als ADMIN an, wenn noch keine Nutzer:innen existieren.

    Das Initialpasswort kommt aus dem Secret ``admin-bootstrap`` und muss beim ersten
    Login geändert werden (``must_change_password``). Ab M4 erzwingt der erste Login
    zusätzlich die MFA-Einrichtung. Gibt ``True`` zurück, wenn ein Konto angelegt wurde.
    """
    settings = get_settings()
    if settings.admin_bootstrap_password is None:
        return False
    if db.scalar(select(func.count()).select_from(User)):
        return False
    admin = User(
        email=settings.admin_bootstrap_email,
        password_hash=hash_password(settings.admin_bootstrap_password.get_secret_value()),
        role=Role.ADMIN,
        must_change_password=True,
    )
    db.add(admin)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()  # parallel gestartete Instanz war schneller
        return False
    audit.record(
        db,
        Action.ADMIN_BOOTSTRAP,
        AuditOutcome.SUCCESS,
        actor_id=admin.id,
        target_type="user",
        target_id=str(admin.id),
    )
    db.commit()
    logger.info("Admin-Konto angelegt", extra={"event": "admin_bootstrap"})
    return True
