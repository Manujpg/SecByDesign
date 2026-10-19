"""Zwei-Faktor-Anmeldung mit TOTP nach RFC 6238 (SR-02, ADR A11).

Ablauf für Konten ohne MFA:
    1. ``start_setup``   erzeugt ein neues Secret (verschlüsselt gespeichert, noch inaktiv)
                         und liefert die otpauth-URI für den QR-Code.
    2. ``confirm_setup`` prüft den ersten Code aus der App, aktiviert MFA und gibt
                         einmalig 8 Recovery-Codes aus.

Anmeldung mit MFA:
    Login liefert eine Sitzung mit ``mfa_verified=false`` (5 min). ``verify_login`` prüft
    den Code oder einen Recovery-Code und tauscht die Sitzung gegen eine vollwertige aus.

Sicherheitsmerkmale:
- Secrets AES-GCM-verschlüsselt, an die Nutzer-ID gebunden (siehe ``core/crypto.py``).
- Codes gelten im Fenster ±1 Zeitschritt (±30 s), aber jeder Zeitschritt nur einmal (Replay).
- Nach ``MFA_MAX_FAILURES`` falschen Codes wird die halb angemeldete Sitzung verworfen.
- Recovery-Codes: 50 Bit Zufall, nur als HMAC gespeichert, jeweils einmal verwendbar.
- Für STAFF, DOCTOR und ADMIN ist MFA Pflicht und kann nicht deaktiviert werden.
"""

from __future__ import annotations

import hmac
import logging
import secrets
import time
from dataclasses import dataclass
from datetime import timedelta

import pyotp
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.crypto import DecryptionError, decrypt, encrypt, keyed_hash
from app.core.errors import AppError
from app.core.security import verify_password
from app.core.timeutil import utcnow
from app.models import AuditOutcome, RecoveryCode, Role, User, UserSession
from app.services import audit
from app.services.audit import Action
from app.services.sessions import IssuedSession, create_session, revoke_all_sessions, revoke_session

logger = logging.getLogger("app.mfa")

PRIVILEGED_ROLES = frozenset({Role.STAFF, Role.DOCTOR, Role.ADMIN})
RECOVERY_CODE_COUNT = 8
_TOTP_INTERVAL = 30
_TOTP_WINDOW = 1  # akzeptiert vorherigen, aktuellen und nächsten Zeitschritt (Uhrabweichung)
_SECRET_PURPOSE = b"mfa-secret/v1"
_RECOVERY_PURPOSE = b"mfa-recovery/v1"
# Ohne leicht verwechselbare Zeichen (0/o, 1/l/i) für das Abtippen vom Papier.
_RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"


def _clock() -> float:
    """Zeitquelle für TOTP; in Tests austauschbar."""
    return time.time()


def mfa_required_for(user: User) -> bool:
    return user.role in PRIVILEGED_ROLES


# ---------------------------------------------------------------------------
# Secret-Verwaltung
# ---------------------------------------------------------------------------


def _store_secret(user: User, secret: str) -> None:
    user.mfa_secret_enc = encrypt(
        secret.encode(), purpose=_SECRET_PURPOSE, associated_data=user.id.bytes
    )


def _load_secret(user: User) -> str:
    if user.mfa_secret_enc is None:
        raise AppError(409, "mfa_not_set_up", "Die Zwei-Faktor-Anmeldung ist nicht eingerichtet.")
    try:
        return decrypt(
            user.mfa_secret_enc, purpose=_SECRET_PURPOSE, associated_data=user.id.bytes
        ).decode()
    except DecryptionError:
        # Manipulierter Datensatz oder falscher Schlüssel: nicht verraten, nur protokollieren.
        logger.error("TOTP-Secret nicht entschlüsselbar", extra={"event": "mfa_decrypt_failed"})
        raise AppError(500, "internal_error", "Ein interner Fehler ist aufgetreten.") from None


def _matching_step(secret: str, code: str) -> int | None:
    """Liefert den Zeitschritt, zu dem der Code passt, oder ``None``.

    Vergleich in konstanter Zeit; alle Fenster-Schritte werden immer geprüft.
    """
    totp = pyotp.TOTP(secret, interval=_TOTP_INTERVAL)
    current = int(_clock() // _TOTP_INTERVAL)
    match: int | None = None
    for step in range(current - _TOTP_WINDOW, current + _TOTP_WINDOW + 1):
        if hmac.compare_digest(totp.at(step * _TOTP_INTERVAL), code):
            match = step
    return match


def _check_totp(user: User, code: str) -> bool:
    step = _matching_step(_load_secret(user), code)
    if step is None:
        return False
    if user.mfa_last_used_step is not None and step <= user.mfa_last_used_step:
        return False  # Code (oder ein älterer) wurde schon verwendet
    user.mfa_last_used_step = step
    return True


def _new_recovery_codes(db: Session, user: User) -> list[str]:
    db.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user.id))
    codes = []
    for _ in range(RECOVERY_CODE_COUNT):
        raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(10))
        codes.append(f"{raw[:5]}-{raw[5:]}")
        db.add(RecoveryCode(user_id=user.id, code_hash=keyed_hash(raw, purpose=_RECOVERY_PURPOSE)))
    return codes


def _use_recovery_code(db: Session, user: User, code: str) -> bool:
    normalized = code.replace("-", "").replace(" ", "").lower()
    record = db.scalar(
        select(RecoveryCode).where(
            RecoveryCode.user_id == user.id,
            RecoveryCode.code_hash == keyed_hash(normalized, purpose=_RECOVERY_PURPOSE),
            RecoveryCode.used_at.is_(None),
        )
    )
    if record is None:
        return False
    record.used_at = utcnow()
    return True


# ---------------------------------------------------------------------------
# Einrichtung
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SetupData:
    secret: str
    otpauth_uri: str


def start_setup(db: Session, user: User, *, ip: str | None) -> SetupData:
    if user.mfa_enabled:
        raise AppError(409, "mfa_already_enabled", "Die Zwei-Faktor-Anmeldung ist bereits aktiv.")
    secret = pyotp.random_base32()  # 160 Bit, wie von RFC 4226 empfohlen
    _store_secret(user, secret)
    user.mfa_last_used_step = None
    audit.record(
        db,
        Action.MFA_SETUP,
        AuditOutcome.SUCCESS,
        actor_id=user.id,
        target_type="user",
        target_id=str(user.id),
        ip=ip,
    )
    uri = pyotp.TOTP(secret, interval=_TOTP_INTERVAL).provisioning_uri(
        name=user.email, issuer_name=get_settings().mfa_issuer
    )
    return SetupData(secret=secret, otpauth_uri=uri)


def confirm_setup(
    db: Session, user: User, code: str, *, ip: str | None, user_agent: str | None
) -> tuple[list[str], IssuedSession]:
    if user.mfa_enabled:
        raise AppError(409, "mfa_already_enabled", "Die Zwei-Faktor-Anmeldung ist bereits aktiv.")
    if not _check_totp(user, code):
        audit.record(
            db,
            Action.MFA_ENABLE,
            AuditOutcome.FAILURE,
            actor_id=user.id,
            target_type="user",
            target_id=str(user.id),
            ip=ip,
        )
        db.commit()
        raise AppError(
            422, "invalid_mfa_code", "Der Code ist ungültig. Bitte versuchen Sie es erneut."
        )
    user.mfa_enabled = True
    codes = _new_recovery_codes(db, user)
    # Sicherheitsrelevante Änderung: alle bestehenden Sitzungen beenden, neue ausstellen.
    revoke_all_sessions(db, user.id)
    issued = create_session(db, user, mfa_verified=True, ip=ip, user_agent=user_agent)
    audit.record(
        db,
        Action.MFA_ENABLE,
        AuditOutcome.SUCCESS,
        actor_id=user.id,
        target_type="user",
        target_id=str(user.id),
        ip=ip,
    )
    return codes, issued


# ---------------------------------------------------------------------------
# Anmeldung
# ---------------------------------------------------------------------------


def verify_login(
    db: Session,
    user: User,
    session: UserSession,
    *,
    code: str | None,
    recovery_code: str | None,
    ip: str | None,
    user_agent: str | None,
) -> IssuedSession:
    if session.mfa_verified:
        raise AppError(409, "mfa_already_verified", "Die Anmeldung ist bereits bestätigt.")
    if not user.mfa_enabled:
        raise AppError(409, "mfa_not_set_up", "Die Zwei-Faktor-Anmeldung ist nicht eingerichtet.")

    used_recovery = False
    if code is not None:
        ok = _check_totp(user, code)
    else:
        ok = recovery_code is not None and _use_recovery_code(db, user, recovery_code)
        used_recovery = ok

    if not ok:
        audit.record(
            db,
            Action.MFA_VERIFY,
            AuditOutcome.FAILURE,
            actor_id=user.id,
            target_type="session",
            target_id=str(session.id),
            ip=ip,
        )
        settings = get_settings()
        session_failures = audit.count_recent(
            db,
            Action.MFA_VERIFY,
            AuditOutcome.FAILURE,
            window=timedelta(minutes=settings.mfa_pending_minutes),
            target_id=str(session.id),
        )
        # Kontoweit: wer das Passwort kennt, könnte sonst mit immer neuen Logins
        # beliebig viele Codes durchprobieren.
        account_failures = audit.count_recent(
            db,
            Action.MFA_VERIFY,
            AuditOutcome.FAILURE,
            window=timedelta(minutes=settings.login_window_minutes),
            actor_id=user.id,
        )
        if account_failures >= settings.login_max_failures:
            user.locked_until = utcnow() + timedelta(minutes=settings.login_window_minutes)
            audit.record(
                db,
                Action.ACCOUNT_LOCKED,
                AuditOutcome.SUCCESS,
                actor_id=user.id,
                target_type="user",
                target_id=str(user.id),
                ip=ip,
            )
            revoke_session(db, session)
            db.commit()
            raise AppError(
                429,
                "too_many_attempts",
                "Zu viele Versuche. Bitte warten Sie einige Minuten und versuchen Sie es erneut.",
                headers={"Retry-After": str(settings.login_window_minutes * 60)},
            )
        if session_failures >= settings.mfa_max_failures:
            # Halb angemeldete Sitzung verwerfen, Login mit Passwort ist neu nötig.
            revoke_session(db, session)
            db.commit()
            raise AppError(
                401,
                "mfa_too_many_attempts",
                "Zu viele ungültige Codes. Bitte melden Sie sich erneut an.",
            )
        db.commit()
        raise AppError(
            422, "invalid_mfa_code", "Der Code ist ungültig. Bitte versuchen Sie es erneut."
        )

    # Zwischensitzung durch vollwertige Sitzung mit neuem Token ersetzen (Rotation).
    revoke_session(db, session)
    issued = create_session(db, user, mfa_verified=True, ip=ip, user_agent=user_agent)
    audit.record(
        db,
        Action.MFA_RECOVERY_USED if used_recovery else Action.MFA_VERIFY,
        AuditOutcome.SUCCESS,
        actor_id=user.id,
        target_type="user",
        target_id=str(user.id),
        ip=ip,
    )
    return issued


# ---------------------------------------------------------------------------
# Verwaltung
# ---------------------------------------------------------------------------


def regenerate_recovery_codes(db: Session, user: User, code: str, *, ip: str | None) -> list[str]:
    if not user.mfa_enabled:
        raise AppError(409, "mfa_not_set_up", "Die Zwei-Faktor-Anmeldung ist nicht eingerichtet.")
    if not _check_totp(user, code):
        db.commit()
        raise AppError(
            422, "invalid_mfa_code", "Der Code ist ungültig. Bitte versuchen Sie es erneut."
        )
    codes = _new_recovery_codes(db, user)
    audit.record(
        db,
        Action.MFA_RECOVERY_REGENERATE,
        AuditOutcome.SUCCESS,
        actor_id=user.id,
        target_type="user",
        target_id=str(user.id),
        ip=ip,
    )
    return codes


def disable(
    db: Session,
    user: User,
    session: UserSession,
    *,
    password: str,
    code: str,
    ip: str | None,
) -> None:
    if mfa_required_for(user):
        raise AppError(
            403,
            "mfa_mandatory",
            "Für Ihre Rolle ist die Zwei-Faktor-Anmeldung verpflichtend.",
        )
    if not user.mfa_enabled:
        raise AppError(409, "mfa_not_set_up", "Die Zwei-Faktor-Anmeldung ist nicht eingerichtet.")
    if not verify_password(user.password_hash, password) or not _check_totp(user, code):
        audit.record(
            db,
            Action.MFA_DISABLE,
            AuditOutcome.FAILURE,
            actor_id=user.id,
            target_type="user",
            target_id=str(user.id),
            ip=ip,
        )
        db.commit()
        raise AppError(403, "invalid_credentials", "Passwort oder Code ist ungültig.")
    user.mfa_enabled = False
    user.mfa_secret_enc = None
    user.mfa_last_used_step = None
    db.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user.id))
    # Andere Geräte abmelden; die aktuelle Sitzung bleibt bestehen.
    db.execute(
        delete(UserSession).where(UserSession.user_id == user.id, UserSession.id != session.id)
    )
    audit.record(
        db,
        Action.MFA_DISABLE,
        AuditOutcome.SUCCESS,
        actor_id=user.id,
        target_type="user",
        target_id=str(user.id),
        ip=ip,
    )
