"""Tests für die Zwei-Faktor-Anmeldung (M4, SR-02).

Die TOTP-Uhr wird per Fixture gesteuert: Wegen des Replay-Schutzes gilt jeder Code
nur einmal, Tests müssen also gezielt in den nächsten 30-Sekunden-Schritt springen.
"""

from __future__ import annotations

import re
import uuid
from typing import Annotated
from urllib.parse import parse_qs, unquote, urlsplit

import pyotp
import pytest
from fastapi import APIRouter, Depends
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import SESSION_COOKIE, Principal, require_roles
from app.core.crypto import DecryptionError, decrypt, encrypt
from app.models import AuditLog, RecoveryCode, Role, User, UserSession
from app.services import auth as auth_service
from app.services import mfa as mfa_service
from app.services.audit import Action
from tests.conftest import make_client
from tests.test_auth import OTHER_STRONG, STRONG, _change, _login, _register

T0 = 1_800_000_000.0  # fester Startzeitpunkt, Vielfaches von 30


class Clock:
    def __init__(self) -> None:
        self.now = T0

    def step(self, n: int = 1) -> None:
        self.now += 30 * n


@pytest.fixture
def clock(monkeypatch) -> Clock:
    c = Clock()
    monkeypatch.setattr(mfa_service, "_clock", lambda: c.now)
    return c


def code(secret: str, clock: Clock, offset_steps: int = 0) -> str:
    return pyotp.TOTP(secret).at(clock.now + 30 * offset_steps)


def _setup(client: TestClient, clock: Clock) -> tuple[str, list[str]]:
    res = client.post("/api/v1/auth/mfa/setup")
    assert res.status_code == 200, res.text
    secret = res.json()["secret"]
    confirm = client.post("/api/v1/auth/mfa/confirm", json={"code": code(secret, clock)})
    assert confirm.status_code == 200, confirm.text
    return secret, confirm.json()["recovery_codes"]


def _verify(client: TestClient, **body):
    return client.post("/api/v1/auth/mfa/verify", json=body)


@pytest.fixture
def mfa_patient(client: TestClient, clock: Clock) -> tuple[str, list[str]]:
    """Patientin mit eingerichteter MFA; der Client ist danach abgemeldet."""
    assert _register(client).status_code == 202
    assert _login(client).status_code == 200
    secret, codes = _setup(client, clock)
    client.post("/api/v1/auth/logout")
    clock.step()
    return secret, codes


# --- Einrichtung ------------------------------------------------------------------


def test_setup_returns_provisioning_uri(client: TestClient, clock, settings) -> None:
    _register(client)
    _login(client)
    res = client.post("/api/v1/auth/mfa/setup").json()
    assert re.fullmatch(r"[A-Z2-7]{32}", res["secret"])  # 160 Bit Base32
    uri = urlsplit(res["otpauth_uri"])
    assert uri.scheme == "otpauth"
    assert uri.netloc == "totp"
    assert "anna@example.org" in unquote(uri.path)
    params = parse_qs(uri.query)
    assert params["issuer"] == [settings.mfa_issuer]
    assert params["secret"] == [res["secret"]]


def test_secret_stored_encrypted(client: TestClient, db: Session, clock) -> None:
    _register(client)
    _login(client)
    secret = client.post("/api/v1/auth/mfa/setup").json()["secret"]
    user = db.scalar(select(User))
    assert user.mfa_secret_enc is not None
    assert secret.encode() not in user.mfa_secret_enc
    assert user.mfa_enabled is False  # erst nach Bestätigung aktiv


def test_confirm_enables_mfa_and_returns_recovery_codes(
    client: TestClient, db: Session, clock
) -> None:
    _register(client)
    _login(client)
    old_token = client.cookies.get(SESSION_COOKIE)
    _, codes = _setup(client, clock)
    assert len(codes) == 8
    assert len(set(codes)) == 8
    assert all(re.fullmatch(r"[a-z2-9]{5}-[a-z2-9]{5}", c) for c in codes)
    user = db.scalar(select(User))
    assert user.mfa_enabled is True
    stored = list(db.scalars(select(RecoveryCode)))
    assert len(stored) == 8
    assert not any(c.replace("-", "") in r.code_hash for c in codes for r in stored)
    assert client.cookies.get(SESSION_COOKIE) != old_token  # Sitzung rotiert


def test_confirm_with_wrong_code(client: TestClient, db: Session, clock) -> None:
    _register(client)
    _login(client)
    client.post("/api/v1/auth/mfa/setup")
    res = client.post("/api/v1/auth/mfa/confirm", json={"code": "000000"})
    assert res.status_code == 422
    assert res.json()["error"]["code"] == "invalid_mfa_code"
    assert db.scalar(select(User)).mfa_enabled is False


def test_confirm_logs_out_other_devices(client: TestClient, clock) -> None:
    _register(client)
    other = make_client(client.app)
    _login(other)
    _login(client)
    _setup(client, clock)
    assert other.get("/api/v1/auth/me").status_code == 401
    assert client.get("/api/v1/auth/me").status_code == 200


def test_setup_twice_rejected(client: TestClient, clock) -> None:
    _register(client)
    _login(client)
    _setup(client, clock)
    assert client.post("/api/v1/auth/mfa/setup").status_code == 409


def test_setup_requires_login(client: TestClient) -> None:
    assert client.post("/api/v1/auth/mfa/setup").status_code == 401


# --- Anmeldung mit MFA ----------------------------------------------------------------


def test_login_requires_second_factor(client: TestClient, mfa_patient, clock) -> None:
    secret, _ = mfa_patient
    res = _login(client)
    assert res.json()["mfa_required"] is True
    pending = client.cookies.get(SESSION_COOKIE)
    assert client.get("/api/v1/auth/me").status_code == 401
    # Mit Zwischensitzung darf keine MFA-Einrichtung o. Ä. passieren.
    assert client.post("/api/v1/auth/mfa/setup").status_code == 401

    ok = _verify(client, code=code(secret, clock))
    assert ok.status_code == 200
    assert client.cookies.get(SESSION_COOKIE) != pending  # neues Token
    assert client.get("/api/v1/auth/me").status_code == 200
    # Die Zwischensitzung ist verbraucht.
    replay = make_client(client.app)
    replay.cookies.set(SESSION_COOKIE, pending)
    assert replay.get("/api/v1/auth/session").status_code == 401


def test_code_cannot_be_used_twice(client: TestClient, mfa_patient, clock) -> None:
    secret, _ = mfa_patient
    current = code(secret, clock)
    _login(client)
    assert _verify(client, code=current).status_code == 200
    client.post("/api/v1/auth/logout")
    _login(client)
    res = _verify(client, code=current)  # gleicher Zeitschritt: Replay
    assert res.status_code == 422


def test_time_window(client: TestClient, mfa_patient, clock) -> None:
    secret, _ = mfa_patient
    # Einen Schritt weiter, damit der vorherige Schritt nicht schon bei der Einrichtung
    # verbraucht wurde (sonst greift zu Recht der Replay-Schutz).
    clock.step()
    _login(client)
    assert _verify(client, code=code(secret, clock, -2)).status_code == 422  # zu alt
    assert _verify(client, code=code(secret, clock, +2)).status_code == 422  # zu weit vorn
    assert _verify(client, code=code(secret, clock, -1)).status_code == 200  # 30 s Toleranz


def test_too_many_wrong_codes_kill_pending_session(
    client: TestClient, db: Session, mfa_patient, clock, settings
) -> None:
    _login(client)
    for _ in range(settings.mfa_max_failures - 1):
        assert _verify(client, code="000000").status_code == 422
    last = _verify(client, code="000000")
    assert last.status_code == 401
    assert last.json()["error"]["code"] == "mfa_too_many_attempts"
    db.expire_all()
    assert db.scalar(select(UserSession)) is None


def test_account_locked_after_mfa_brute_force(
    client: TestClient, db: Session, mfa_patient, clock, settings, monkeypatch
) -> None:
    # Ein Angreifer mit Passwort holt sich immer neue Zwischensitzungen.
    monkeypatch.setattr(settings, "mfa_max_failures", 3)
    statuses = []
    for _ in range(4):
        _login(client)
        for _ in range(3):
            statuses.append(_verify(client, code="000000").status_code)
            if statuses[-1] != 422:
                break
        if statuses[-1] == 429:
            break
    assert statuses[-1] == 429
    assert _login(client).status_code == 429  # Konto gesperrt, auch mit richtigem Passwort


def test_recovery_code_login_single_use(client: TestClient, mfa_patient, db: Session) -> None:
    _, codes = mfa_patient
    _login(client)
    assert _verify(client, recovery_code=codes[0].upper().replace("-", "")).status_code == 200
    client.post("/api/v1/auth/logout")
    _login(client)
    assert _verify(client, recovery_code=codes[0]).status_code == 422
    assert _verify(client, recovery_code=codes[1]).status_code == 200
    used = [a for a in db.scalars(select(AuditLog)) if a.action == Action.MFA_RECOVERY_USED]
    assert len(used) == 2


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"code": "123456", "recovery_code": "abcde-fghjk"},
        {"code": "12345"},
        {"code": "12345a"},
        {"recovery_code": "x" * 40},
        {"code": "123456", "extra": 1},
    ],
)
def test_verify_input_validation(client: TestClient, mfa_patient, body: dict) -> None:
    _login(client)
    assert _verify(client, **body).status_code == 422


def test_verify_without_pending_session(client: TestClient, clock) -> None:
    _register(client)
    _login(client)  # ohne MFA: Sitzung ist sofort vollwertig
    assert _verify(client, code="123456").status_code == 409


# --- Verwaltung -------------------------------------------------------------------------


def test_regenerate_recovery_codes(client: TestClient, mfa_patient, clock) -> None:
    secret, old_codes = mfa_patient
    _login(client)
    _verify(client, code=code(secret, clock))
    clock.step()
    res = client.post("/api/v1/auth/mfa/recovery-codes", json={"code": code(secret, clock)})
    assert res.status_code == 200
    new_codes = res.json()["recovery_codes"]
    assert set(new_codes).isdisjoint(old_codes)
    client.post("/api/v1/auth/logout")
    _login(client)
    assert _verify(client, recovery_code=old_codes[0]).status_code == 422
    assert _verify(client, recovery_code=new_codes[0]).status_code == 200


def test_patient_can_disable_mfa(client: TestClient, db: Session, mfa_patient, clock) -> None:
    secret, _ = mfa_patient
    _login(client)
    _verify(client, code=code(secret, clock))
    clock.step()
    wrong = client.post(
        "/api/v1/auth/mfa/disable",
        json={"password": "Falsch-Falsch-123", "code": code(secret, clock)},
    )
    assert wrong.status_code == 403
    res = client.post(
        "/api/v1/auth/mfa/disable", json={"password": STRONG, "code": code(secret, clock)}
    )
    assert res.status_code == 204
    db.expire_all()
    user = db.scalar(select(User))
    assert user.mfa_enabled is False
    assert user.mfa_secret_enc is None
    assert db.scalar(select(RecoveryCode)) is None
    client.post("/api/v1/auth/logout")
    assert _login(client).json()["mfa_required"] is False


# --- Pflicht für privilegierte Rollen ------------------------------------------------


@pytest.fixture
def admin_route(app):
    router = APIRouter(prefix="/api/v1/test")

    @router.get("/admin")
    def admin_only(p: Annotated[Principal, Depends(require_roles(Role.ADMIN))]) -> dict[str, str]:
        return {"ok": "admin"}

    app.include_router(router)


def test_admin_onboarding_password_then_mfa(
    client: TestClient, db: Session, settings, monkeypatch, clock, admin_route
) -> None:
    initial = "Initial-Bootstrap-PW-1234"
    monkeypatch.setattr(settings, "admin_bootstrap_password", SecretStr(initial))
    auth_service.bootstrap_admin(db)
    email = settings.admin_bootstrap_email

    _login(client, email=email, password=initial)
    # 1. Ohne Passwortwechsel weder Fachfunktion noch MFA-Einrichtung
    assert client.get("/api/v1/test/admin").json()["error"]["code"] == "password_change_required"
    assert client.post("/api/v1/auth/mfa/setup").status_code == 403
    assert _change(client, initial, OTHER_STRONG).status_code == 200
    # 2. Ohne MFA keine Fachfunktion
    blocked = client.get("/api/v1/test/admin")
    assert blocked.status_code == 403
    assert blocked.json()["error"]["code"] == "mfa_setup_required"
    assert client.get("/api/v1/auth/me").json()["mfa_setup_required"] is True
    # 3. Nach Einrichtung Zugriff
    secret, _ = _setup(client, clock)
    assert client.get("/api/v1/test/admin").json() == {"ok": "admin"}
    # 4. Abschalten ist für Admins verboten
    clock.step()
    res = client.post(
        "/api/v1/auth/mfa/disable", json={"password": OTHER_STRONG, "code": code(secret, clock)}
    )
    assert res.status_code == 403
    assert res.json()["error"]["code"] == "mfa_mandatory"
    # 5. Nächster Login verlangt den zweiten Faktor
    client.post("/api/v1/auth/logout")
    clock.step()
    assert _login(client, email=email, password=OTHER_STRONG).json()["mfa_required"] is True
    assert client.get("/api/v1/test/admin").status_code == 401
    _verify(client, code=code(secret, clock))
    assert client.get("/api/v1/test/admin").status_code == 200


# --- Kryptografie und Audit -----------------------------------------------------------


def test_ciphertext_bound_to_user() -> None:
    a, b = uuid.uuid4(), uuid.uuid4()
    blob = encrypt(b"JBSWY3DPEHPK3PXP", purpose=b"mfa-secret/v1", associated_data=a.bytes)
    assert decrypt(blob, purpose=b"mfa-secret/v1", associated_data=a.bytes) == b"JBSWY3DPEHPK3PXP"
    with pytest.raises(DecryptionError):
        decrypt(blob, purpose=b"mfa-secret/v1", associated_data=b.bytes)  # anderes Konto
    with pytest.raises(DecryptionError):
        decrypt(blob, purpose=b"anderer-zweck", associated_data=a.bytes)
    tampered = blob[:-1] + bytes([blob[-1] ^ 1])
    with pytest.raises(DecryptionError):
        decrypt(tampered, purpose=b"mfa-secret/v1", associated_data=a.bytes)


def test_swapped_secret_is_not_usable(client: TestClient, db: Session, clock, mfa_patient) -> None:
    # Ein Angreifer mit DB-Schreibzugriff kopiert sein eigenes Secret in ein fremdes Konto.
    victim = db.scalar(select(User))
    other = make_client(client.app)
    _register(other, email="mallory@example.org", first_name="Mallory")
    _login(other, email="mallory@example.org")
    _setup(other, clock)
    attacker = db.scalar(select(User).where(User.email == "mallory@example.org"))
    victim.mfa_secret_enc = attacker.mfa_secret_enc
    db.commit()
    _login(client)
    res = _verify(client, code="123456")
    assert res.status_code == 500
    assert res.json()["error"]["code"] == "internal_error"


def test_audit_contains_mfa_events_without_secrets(
    client: TestClient, db: Session, mfa_patient, clock
) -> None:
    secret, codes = mfa_patient
    _login(client)
    _verify(client, code="000000")
    _verify(client, code=code(secret, clock))
    db.expire_all()
    rows = list(db.scalars(select(AuditLog)))
    actions = {r.action for r in rows}
    assert {Action.MFA_SETUP, Action.MFA_ENABLE, Action.MFA_VERIFY} <= actions
    dump = " ".join(str(v) for r in rows for v in vars(r).values())
    assert secret not in dump
    assert not any(c in dump for c in codes)
