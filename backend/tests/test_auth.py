"""Tests für Registrierung, Login, Sitzungen, Sperren, CSRF und Admin-Bootstrap (M3).

Bezug: SR-01 (Authentifizierung), SR-03 (Rollenprüfung), SR-04 (Validierung),
SR-06 (keine Secrets im Log), SR-07 (Sitzungen/CSRF), SR-08 (Brute-Force), SR-11 (Audit).
"""

from __future__ import annotations

import hashlib
from datetime import timedelta
from typing import Annotated

import pytest
from argon2 import PasswordHasher
from fastapi import APIRouter, Depends
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import SESSION_COOKIE, Principal, require_active_user, require_roles
from app.core.timeutil import utcnow
from app.models import AuditLog, AuditOutcome, Role, User, UserSession
from app.services import auth as auth_service
from app.services.audit import Action
from tests.conftest import ORIGIN, make_client

STRONG = "Lindenblüte-Sprechstunde-2026!"
OTHER_STRONG = "Wartezimmer-Kaffee-Ostseewind-7"


def _register(client: TestClient, email: str = "anna@example.org", password: str = STRONG, **kw):
    payload = {
        "email": email,
        "password": password,
        "first_name": "Anna",
        "last_name": "Muster",
        "birth_date": "1990-05-17",
        "insurance_type": "GKV",
    }
    payload.update(kw)
    return client.post("/api/v1/auth/register", json=payload)


def _login(client: TestClient, email: str = "anna@example.org", password: str = STRONG):
    return client.post("/api/v1/auth/login", json={"email": email, "password": password})


def _audit(db: Session, action: str) -> list[AuditLog]:
    db.expire_all()
    return list(db.scalars(select(AuditLog).where(AuditLog.action == action)))


@pytest.fixture
def patient(client: TestClient) -> str:
    assert _register(client).status_code == 202
    return "anna@example.org"


# --- Registrierung -------------------------------------------------------------


def test_register_and_login(client: TestClient, db: Session) -> None:
    assert _register(client).status_code == 202
    res = _login(client)
    assert res.status_code == 200
    body = res.json()
    assert body["user"]["role"] == "PATIENT"
    assert body["mfa_required"] is False
    me = client.get("/api/v1/auth/me")
    assert me.status_code == 200
    assert me.json()["email"] == "anna@example.org"


def test_password_stored_only_as_argon2id(client: TestClient, db: Session) -> None:
    _register(client)
    user = db.scalar(select(User))
    assert user.password_hash.startswith("$argon2id$")
    assert STRONG not in user.password_hash


def test_register_role_injection_rejected(client: TestClient, db: Session) -> None:
    res = _register(client, role="ADMIN")
    assert res.status_code == 422
    assert "body.role" in {d["field"] for d in res.json()["error"]["details"]}
    assert db.scalar(select(User)) is None


def test_register_duplicate_email_gives_identical_response(client: TestClient, db: Session) -> None:
    first = _register(client)
    second = _register(client, email="ANNA@example.org", password=OTHER_STRONG)
    assert first.status_code == second.status_code == 202
    assert first.json() == second.json()
    assert len(list(db.scalars(select(User)))) == 1
    failures = [a for a in _audit(db, Action.REGISTER) if a.outcome == AuditOutcome.FAILURE]
    assert len(failures) == 1
    # Das ursprüngliche Passwort bleibt gültig, das zweite nicht.
    assert _login(client, password=OTHER_STRONG).status_code == 401
    assert _login(client).status_code == 200


@pytest.mark.parametrize(
    ("password", "reason"),
    [
        ("kurz", "too_short"),
        ("passwort1234", "too_weak"),
        ("qwertzuiop123", "too_weak"),
        ("anna.mustermann-Geheim!", "contains_personal_data"),
    ],
)
def test_register_weak_passwords(client: TestClient, password: str, reason: str) -> None:
    res = _register(client, email="anna.mustermann@example.org", password=password)
    assert res.status_code == 422
    assert res.json()["error"]["code"] == f"weak_password.{reason}"


@pytest.mark.parametrize(
    "override",
    [
        {"first_name": "<script>"},
        {"last_name": ""},
        {"first_name": "x" * 101},
        {"birth_date": "1850-01-01"},
        {"birth_date": "2999-01-01"},
        {"phone": "abc"},
        {"insurance_type": "GOLD"},
        {"email": "keine-mail"},
        {"password": "x" * 129},
    ],
)
def test_register_input_validation(client: TestClient, override: dict) -> None:
    res = _register(client, **override)
    assert res.status_code == 422


def test_register_accepts_international_names(client: TestClient) -> None:
    assert _register(client, first_name="Zoë-Ångström", last_name="O'Neil").status_code == 202


# --- Login und Enumeration --------------------------------------------------------


def test_wrong_password_and_unknown_email_look_identical(client: TestClient, patient) -> None:
    wrong = _login(client, password="Falsches-Passwort-123")
    unknown = _login(client, email="niemand@example.org")
    assert wrong.status_code == unknown.status_code == 401
    strip = lambda r: {k: v for k, v in r.json()["error"].items() if k != "request_id"}  # noqa: E731
    assert strip(wrong) == strip(unknown)


def test_unknown_email_still_runs_password_hash(client: TestClient, monkeypatch) -> None:
    calls: list[str | None] = []
    original = auth_service.verify_password

    def spy(password_hash, password):
        calls.append(password_hash)
        return original(password_hash, password)

    monkeypatch.setattr(auth_service, "verify_password", spy)
    _login(client, email="niemand@example.org")
    assert calls == [None]  # verify_password(None, …) prüft gegen einen Dummy-Hash


def test_email_is_case_insensitive(client: TestClient, patient) -> None:
    assert _login(client, email="  Anna@Example.ORG ").status_code == 200


def test_session_cookie_flags(client: TestClient, patient) -> None:
    res = _login(client)
    cookie = res.headers["set-cookie"]
    assert cookie.startswith(f"{SESSION_COOKIE}=")
    lowered = cookie.lower()
    for flag in ("httponly", "secure", "samesite=strict", "path=/"):
        assert flag in lowered
    assert "domain=" not in lowered


def test_token_only_stored_as_hash(client: TestClient, db: Session, patient) -> None:
    _login(client)
    token = client.cookies.get(SESSION_COOKIE)
    stored = db.scalar(select(UserSession))
    assert stored.token_hash == hashlib.sha256(token.encode()).digest()
    assert token.encode() != stored.token_hash


def test_inactive_user_cannot_login(client: TestClient, db: Session, patient) -> None:
    user = db.scalar(select(User))
    user.is_active = False
    db.commit()
    assert _login(client).status_code == 401


def test_rehash_on_login_when_parameters_change(client: TestClient, db: Session, patient) -> None:
    user = db.scalar(select(User))
    user.password_hash = PasswordHasher(time_cost=2, memory_cost=2048, parallelism=1).hash(STRONG)
    db.commit()
    old_hash = user.password_hash
    assert _login(client).status_code == 200
    db.expire_all()
    assert db.scalar(select(User)).password_hash != old_hash


# --- Brute-Force-Schutz -----------------------------------------------------------


def test_lockout_after_max_failures(client: TestClient, db: Session, patient, settings) -> None:
    for _ in range(settings.login_max_failures):
        assert _login(client, password="Falsches-Passwort-123").status_code == 401
    locked = _login(client)  # selbst das richtige Passwort wird jetzt abgewiesen
    assert locked.status_code == 429
    assert int(locked.headers["retry-after"]) > 0
    assert _audit(db, Action.ACCOUNT_LOCKED)


def test_lockout_also_for_unknown_email(client: TestClient, settings) -> None:
    # Gleiches Verhalten wie bei existierenden Konten: die Sperre verrät kein Konto.
    for _ in range(settings.login_max_failures):
        assert _login(client, email="niemand@example.org").status_code == 401
    assert _login(client, email="niemand@example.org").status_code == 429


def test_success_resets_failure_counter(client: TestClient, patient, settings) -> None:
    for _ in range(settings.login_max_failures - 1):
        _login(client, password="Falsches-Passwort-123")
    assert _login(client).status_code == 200
    for _ in range(settings.login_max_failures - 1):
        assert _login(client, password="Falsches-Passwort-123").status_code == 401


def test_ip_rate_limit(client: TestClient, settings, monkeypatch) -> None:
    monkeypatch.setattr(settings, "login_ip_max_failures", 5)
    for i in range(5):
        _login(client, email=f"user{i}@example.org")
    assert _login(client, email="noch-jemand@example.org").status_code == 429


def test_register_rate_limit_per_ip(client: TestClient, settings, monkeypatch) -> None:
    monkeypatch.setattr(settings, "register_ip_max", 3)
    for i in range(3):
        assert _register(client, email=f"p{i}@example.org").status_code == 202
    assert _register(client, email="p9@example.org").status_code == 429


# --- Sitzungen ------------------------------------------------------------------


def test_logout_invalidates_session_server_side(client: TestClient, db: Session, patient) -> None:
    _login(client)
    token = client.cookies.get(SESSION_COOKIE)
    assert client.post("/api/v1/auth/logout").status_code == 204
    assert db.scalar(select(UserSession)) is None
    # Auch mit dem alten Token (z. B. gestohlen) ist keine Anfrage mehr möglich.
    replay = make_client(client.app)
    replay.cookies.set(SESSION_COOKIE, token)
    assert replay.get("/api/v1/auth/me").status_code == 401


def test_logout_without_session_is_idempotent(client: TestClient) -> None:
    assert client.post("/api/v1/auth/logout").status_code == 204


def test_idle_timeout(client: TestClient, db: Session, patient, settings) -> None:
    _login(client)
    session = db.scalar(select(UserSession))
    session.last_seen_at = utcnow() - timedelta(minutes=settings.session_idle_minutes + 1)
    db.commit()
    assert client.get("/api/v1/auth/me").status_code == 401
    db.expire_all()
    assert db.scalar(select(UserSession)) is None


def test_absolute_timeout(client: TestClient, db: Session, patient) -> None:
    _login(client)
    session = db.scalar(select(UserSession))
    session.expires_at = utcnow() - timedelta(seconds=1)
    db.commit()
    assert client.get("/api/v1/auth/me").status_code == 401


def test_new_login_rotates_session(client: TestClient, db: Session, patient) -> None:
    _login(client)
    first = client.cookies.get(SESSION_COOKIE)
    _login(client)
    second = client.cookies.get(SESSION_COOKIE)
    assert first != second
    db.expire_all()
    assert len(list(db.scalars(select(UserSession)))) == 1  # alte Sitzung wurde gelöscht


@pytest.mark.parametrize("cookie", ["x" * 5000, "a" * 43, "../../etc/passwd", ""])
def test_garbage_session_cookie(client: TestClient, cookie: str) -> None:
    client.cookies.set(SESSION_COOKIE, cookie)
    assert client.get("/api/v1/auth/me").status_code == 401


def test_session_dies_when_user_deactivated(client: TestClient, db: Session, patient) -> None:
    _login(client)
    user = db.scalar(select(User))
    user.is_active = False
    db.commit()
    assert client.get("/api/v1/auth/me").status_code == 401


def test_mfa_pending_session_is_restricted(
    client: TestClient, db: Session, patient, settings
) -> None:
    user = db.scalar(select(User))
    user.mfa_enabled = True
    db.commit()
    res = _login(client)
    assert res.status_code == 200
    assert res.json()["mfa_required"] is True
    assert f"max-age={settings.mfa_pending_minutes * 60}" in res.headers["set-cookie"].lower()
    me = client.get("/api/v1/auth/me")
    assert me.status_code == 401
    assert me.json()["error"]["code"] == "mfa_required"
    assert client.get("/api/v1/auth/session").json()["mfa_required"] is True


# --- Passwortwechsel ----------------------------------------------------------------


def _change(client: TestClient, current: str, new: str):
    return client.post(
        "/api/v1/auth/password", json={"current_password": current, "new_password": new}
    )


def test_password_change_revokes_all_other_sessions(client: TestClient, patient) -> None:
    other_device = make_client(client.app)
    _login(client)
    _login(other_device)
    old_token = client.cookies.get(SESSION_COOKIE)

    res = _change(client, STRONG, OTHER_STRONG)
    assert res.status_code == 200
    assert client.cookies.get(SESSION_COOKIE) != old_token  # neue Sitzung ausgestellt
    assert client.get("/api/v1/auth/me").status_code == 200
    assert other_device.get("/api/v1/auth/me").status_code == 401
    assert _login(make_client(client.app), password=OTHER_STRONG).status_code == 200


def test_password_change_requires_current_password(
    client: TestClient, db: Session, patient
) -> None:
    _login(client)
    res = _change(client, "Falsches-Passwort-123", OTHER_STRONG)
    assert res.status_code == 403
    assert [a for a in _audit(db, Action.CREDENTIAL_CHANGE) if a.outcome == AuditOutcome.FAILURE]


@pytest.mark.parametrize(("new", "code"), [(STRONG, "same_as_old"), ("passwort1234", "too_weak")])
def test_password_change_policy(client: TestClient, patient, new: str, code: str) -> None:
    _login(client)
    res = _change(client, STRONG, new)
    assert res.status_code == 422
    assert res.json()["error"]["code"] == f"weak_password.{code}"


def test_password_change_requires_login(client: TestClient) -> None:
    assert _change(client, STRONG, OTHER_STRONG).status_code == 401


# --- CSRF / Origin ------------------------------------------------------------------


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Origin": "https://evil.example"},
        {"Origin": "null"},
        {"Referer": "https://evil.example/x"},
    ],
)
def test_state_changing_requests_need_allowed_origin(app, headers: dict) -> None:
    raw = TestClient(app, base_url=ORIGIN, raise_server_exceptions=False)
    res = raw.post(
        "/api/v1/auth/login", json={"email": "a@example.org", "password": "x"}, headers=headers
    )
    assert res.status_code == 403
    assert res.json()["error"]["code"] == "origin_rejected"
    assert res.headers["X-Request-ID"]


def test_referer_from_allowed_origin_is_accepted(app) -> None:
    raw = TestClient(app, base_url=ORIGIN, raise_server_exceptions=False)
    res = raw.post(
        "/api/v1/auth/login",
        json={"email": "a@example.org", "password": "x"},
        headers={"Referer": f"{ORIGIN}/login"},
    )
    assert res.status_code == 401  # Origin-Prüfung bestanden, Login scheitert regulär


def test_get_requests_need_no_origin(app) -> None:
    raw = TestClient(app, base_url=ORIGIN, raise_server_exceptions=False)
    assert raw.get("/api/v1/healthz").status_code == 200


# --- Audit-Log ------------------------------------------------------------------------


def test_audit_log_contains_no_email_or_password(client: TestClient, db: Session, patient) -> None:
    _login(client, password="Falsches-Passwort-123")
    _login(client)
    rows = _audit(db, Action.LOGIN)
    assert {r.outcome for r in rows} == {AuditOutcome.SUCCESS, AuditOutcome.FAILURE}
    for row in rows:
        values = " ".join(str(v) for v in vars(row).values())
        assert "anna@example.org" not in values
        assert "Falsches-Passwort" not in values
        assert STRONG not in values
        assert row.request_id


# --- Admin-Bootstrap und Rollen-Gates ----------------------------------------------


@pytest.fixture
def protected_routes(app):
    router = APIRouter(prefix="/api/v1/test")

    @router.get("/active")
    def active(p: Annotated[Principal, Depends(require_active_user)]) -> dict[str, str]:
        return {"role": p.user.role.value}

    @router.get("/admin")
    def admin_only(p: Annotated[Principal, Depends(require_roles(Role.ADMIN))]) -> dict[str, str]:
        return {"ok": "admin"}

    app.include_router(router)


@pytest.fixture
def bootstrap_settings(settings, monkeypatch):
    from pydantic import SecretStr

    monkeypatch.setattr(
        settings, "admin_bootstrap_password", SecretStr("Initial-Bootstrap-PW-1234")
    )
    return settings


def test_bootstrap_creates_single_admin(db: Session, bootstrap_settings) -> None:
    assert auth_service.bootstrap_admin(db) is True
    assert auth_service.bootstrap_admin(db) is False  # nur beim allerersten Start
    admins = list(db.scalars(select(User).where(User.role == Role.ADMIN)))
    assert len(admins) == 1
    assert admins[0].must_change_password is True
    assert _audit(db, Action.ADMIN_BOOTSTRAP)


def test_bootstrap_skipped_when_users_exist(
    client: TestClient, db: Session, bootstrap_settings
) -> None:
    _register(client)
    assert auth_service.bootstrap_admin(db) is False
    assert db.scalar(select(User).where(User.role == Role.ADMIN)) is None


def test_bootstrap_skipped_without_password(db: Session) -> None:
    assert auth_service.bootstrap_admin(db) is False


def test_admin_must_change_initial_password(
    client: TestClient, db: Session, bootstrap_settings, protected_routes
) -> None:
    auth_service.bootstrap_admin(db)
    email = bootstrap_settings.admin_bootstrap_email
    res = _login(client, email=email, password="Initial-Bootstrap-PW-1234")
    assert res.status_code == 200
    assert res.json()["user"]["must_change_password"] is True

    blocked = client.get("/api/v1/test/admin")
    assert blocked.status_code == 403
    assert blocked.json()["error"]["code"] == "password_change_required"
    assert client.get("/api/v1/auth/me").status_code == 200  # erlaubt

    assert _change(client, "Initial-Bootstrap-PW-1234", OTHER_STRONG).status_code == 200
    # Als Nächstes verlangt M4 die MFA-Einrichtung (vollständiger Ablauf in test_mfa.py).
    assert client.get("/api/v1/test/admin").json()["error"]["code"] == "mfa_setup_required"


def test_patient_cannot_access_admin_route(client: TestClient, patient, protected_routes) -> None:
    _login(client)
    assert client.get("/api/v1/test/active").json() == {"role": "PATIENT"}
    res = client.get("/api/v1/test/admin")
    assert res.status_code == 403
    assert res.json()["error"]["code"] == "forbidden"


def test_protected_route_without_session(client: TestClient, protected_routes) -> None:
    assert client.get("/api/v1/test/active").status_code == 401
