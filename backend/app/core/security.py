"""Kryptografische Bausteine: Passwort-Hashing, Passwortregeln, Tokens (SR-01, SR-07).

- Passwörter: Argon2id (argon2-cffi), Parameter aus der Konfiguration.
- Passwortregeln: 12-128 Zeichen, Stärkeprüfung mit zxcvbn (Wörterbücher, häufige
  Passwörter, Tastaturmuster, persönliche Angaben) - angelehnt an NIST SP 800-63B,
  daher keine starren Zeichenklassen-Regeln.
- Sitzungstokens: 256 Bit aus ``secrets``; in der Datenbank liegt nur der SHA-256-Hash.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from functools import lru_cache

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from zxcvbn import zxcvbn

from app.core.config import get_settings

PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 128
# zxcvbn-Score 0-4; 3 = "safely unguessable: moderate protection from offline attacks"
PASSWORD_MIN_SCORE = 3
# zxcvbn wird bei langen Eingaben langsam; die ersten 100 Zeichen reichen zur Bewertung.
_ZXCVBN_MAX_INPUT = 100

SESSION_TOKEN_BYTES = 32  # 256 Bit
_SESSION_TOKEN_LENGTH = 43  # Länge von token_urlsafe(32)


# ---------------------------------------------------------------------------
# Passwort-Hashing
# ---------------------------------------------------------------------------


@lru_cache
def _hasher() -> PasswordHasher:
    s = get_settings()
    return PasswordHasher(
        time_cost=s.argon2_time_cost,
        memory_cost=s.argon2_memory_cost_kib,
        parallelism=s.argon2_parallelism,
    )


@lru_cache
def _dummy_hash() -> str:
    # Wird verifiziert, wenn es die E-Mail nicht gibt: gleiche Rechenzeit wie bei
    # existierenden Konten, damit Antwortzeiten keine Konten verraten.
    return _hasher().hash(secrets.token_urlsafe(16))


def hash_password(password: str) -> str:
    return _hasher().hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    """Prüft ein Passwort in konstanter Größenordnung, auch wenn es kein Konto gibt."""
    try:
        return _hasher().verify(password_hash or _dummy_hash(), password) and (
            password_hash is not None
        )
    except VerifyMismatchError, VerificationError, InvalidHashError:
        return False


def password_needs_rehash(password_hash: str) -> bool:
    return _hasher().check_needs_rehash(password_hash)


# ---------------------------------------------------------------------------
# Passwortregeln
# ---------------------------------------------------------------------------


class WeakPasswordError(ValueError):
    """Passwort erfüllt die Richtlinie nicht. ``reason`` ist ein stabiler Code für das Frontend."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def check_password_policy(password: str, user_inputs: list[str] | None = None) -> None:
    if len(password) < PASSWORD_MIN_LENGTH:
        raise WeakPasswordError("too_short")
    if len(password) > PASSWORD_MAX_LENGTH:
        raise WeakPasswordError("too_long")
    inputs = [i.lower() for i in (user_inputs or []) if i]
    lowered = password.lower()
    # Persönliche Angaben (E-Mail-Teil, Name) dürfen nicht das Passwort bilden.
    for value in inputs:
        for part in {value, value.split("@", 1)[0]}:
            if len(part) >= 4 and part in lowered:
                raise WeakPasswordError("contains_personal_data")
    result = zxcvbn(password[:_ZXCVBN_MAX_INPUT], user_inputs=inputs)
    if result["score"] < PASSWORD_MIN_SCORE:
        raise WeakPasswordError("too_weak")


# ---------------------------------------------------------------------------
# Tokens und Kennungen
# ---------------------------------------------------------------------------


def new_session_token() -> str:
    return secrets.token_urlsafe(SESSION_TOKEN_BYTES)


def hash_token(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()


def is_plausible_session_token(token: str | None) -> bool:
    """Formprüfung vor jeder DB-Abfrage: verhindert, dass beliebig große Cookies gehasht werden."""
    return (
        token is not None
        and len(token) == _SESSION_TOKEN_LENGTH
        and all(c.isalnum() or c in "-_" for c in token)
    )


def login_identifier(email: str) -> str:
    """Pseudonyme Kennung einer Login-E-Mail für Audit-Log und Rate-Limit.

    HMAC statt reinem Hash: Ohne den Server-Schlüssel lässt sich aus dem Audit-Log
    nicht per Wörterbuch auf E-Mail-Adressen zurückrechnen.
    """
    digest = hmac.new(get_settings().secret_key_bytes(), email.encode(), hashlib.sha256)
    return digest.hexdigest()[:32]


def hash_user_agent(user_agent: str | None) -> bytes | None:
    if not user_agent:
        return None
    return hashlib.sha256(user_agent[:512].encode(errors="ignore")).digest()
