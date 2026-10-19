"""Tests für Health, Fehlerbehandlung, Request-ID und Security-Header (SR-04, SR-05, SR-09)."""

from __future__ import annotations

import re

import pytest
from fastapi import APIRouter
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from app.core.config import Settings
from app.core.errors import AppError
from app.db import get_db
from app.schemas import StrictModel

REQUEST_ID = re.compile(r"^[0-9a-f]{32}$")


# --- Health -------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/healthz", "/readyz", "/api/v1/healthz", "/api/v1/readyz"])
def test_health_endpoints_ok(client: TestClient, path: str) -> None:
    res = client.get(path)
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}


def test_readyz_returns_generic_503_when_db_down(app, client: TestClient) -> None:
    class BrokenSession:
        def execute(self, *_a, **_k):
            raise OperationalError("SELECT 1", {}, Exception("host=db user=praxis_app"))

    def _broken():
        yield BrokenSession()

    app.dependency_overrides[get_db] = _broken
    res = client.get("/readyz")
    assert res.status_code == 503
    body = res.text
    assert "praxis_app" not in body
    assert "OperationalError" not in body
    assert res.json()["error"]["code"] == "service_unavailable"


# --- Fehlerformat und Informationslecks ---------------------------------------


def _assert_error_shape(res, status: int, code: str) -> dict:
    assert res.status_code == status
    err = res.json()["error"]
    assert err["code"] == code
    assert isinstance(err["message"], str)
    assert err["message"]
    assert REQUEST_ID.match(err["request_id"])
    assert err["request_id"] == res.headers["X-Request-ID"]
    return err


def test_unknown_route_returns_generic_404(client: TestClient) -> None:
    _assert_error_shape(client.get("/gibt-es-nicht"), 404, "not_found")


def test_wrong_method_returns_405_with_allow_header(client: TestClient) -> None:
    res = client.post("/healthz")
    _assert_error_shape(res, 405, "method_not_allowed")
    assert "GET" in res.headers["allow"]


def test_unhandled_exception_returns_generic_500_without_traceback(app, client) -> None:
    router = APIRouter()

    @router.get("/boom")
    def boom() -> None:
        raise RuntimeError("geheime Interna: /etc/passwd, DB_PASSWORD=xyz")

    app.include_router(router)
    res = client.get("/boom")
    _assert_error_shape(res, 500, "internal_error")
    assert "Traceback" not in res.text
    assert "geheime" not in res.text
    assert "RuntimeError" not in res.text
    # Security-Header auch auf der 500-Antwort
    assert res.headers["X-Content-Type-Options"] == "nosniff"


def test_app_error_uses_client_message(app, client) -> None:
    router = APIRouter()

    @router.get("/konflikt")
    def konflikt() -> None:
        raise AppError(409, "slot_taken", "Dieser Termin ist leider schon vergeben.")

    app.include_router(router)
    err = _assert_error_shape(client.get("/konflikt"), 409, "slot_taken")
    assert err["message"] == "Dieser Termin ist leider schon vergeben."


class _Payload(StrictModel):
    email: str
    age: int


def test_validation_error_does_not_echo_input(app, client) -> None:
    router = APIRouter()

    @router.post("/echo")
    def echo(payload: _Payload) -> dict[str, str]:
        return {"ok": payload.email}

    app.include_router(router)
    secret_input = "<script>alert('xss')</script>"
    res = client.post("/echo", json={"email": "a@b.de", "age": secret_input, "role": "ADMIN"})
    err = _assert_error_shape(res, 422, "validation_error")
    assert secret_input not in res.text
    fields = {d["field"] for d in err["details"]}
    # Unbekanntes Feld "role" wird abgelehnt (extra="forbid"), nicht ignoriert.
    assert "body.role" in fields
    assert "body.age" in fields


# --- Request-ID und Security-Header -------------------------------------------


def test_request_id_is_server_generated(client: TestClient) -> None:
    res = client.get("/healthz", headers={"X-Request-ID": "angreifer-gesteuert"})
    assert REQUEST_ID.match(res.headers["X-Request-ID"])
    assert res.headers["X-Request-ID"] != "angreifer-gesteuert"


def test_security_headers_present(client: TestClient) -> None:
    h = client.get("/healthz").headers
    assert h["X-Content-Type-Options"] == "nosniff"
    assert h["X-Frame-Options"] == "DENY"
    assert h["Referrer-Policy"] == "no-referrer"
    assert "default-src 'none'" in h["Content-Security-Policy"]
    assert h["Cache-Control"] == "no-store"
    assert "server" not in {k.lower() for k in h}


def test_openapi_disabled_outside_dev(client: TestClient) -> None:
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


# --- Konfiguration -------------------------------------------------------------


def test_prod_requires_db_password(monkeypatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("DB_PASSWORD", raising=False)
    with pytest.raises(ValueError, match="DB_PASSWORD"):
        Settings(app_env="prod", _env_file=None)


def test_prod_rejects_database_url(monkeypatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "sqlite:///x.db")
    with pytest.raises(ValueError, match="DATABASE_URL"):
        Settings(app_env="prod", db_password="x", app_secret_key="k" * 32, _env_file=None)


def test_password_not_in_settings_repr(monkeypatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    s = Settings(
        app_env="prod", db_password="SuperGeheim123", app_secret_key="k" * 32, _env_file=None
    )
    assert "SuperGeheim123" not in repr(s)
    assert "SuperGeheim123" not in s.sqlalchemy_url().render_as_string(hide_password=True)


def test_invalid_app_role_rejected() -> None:
    with pytest.raises(ValueError, match="Rollenname"):
        Settings(app_env="test", db_app_role="x; DROP TABLE users", _env_file=None)


def test_prod_requires_app_secret_key(monkeypatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(ValueError, match="APP_SECRET_KEY"):
        Settings(app_env="prod", db_password="x", _env_file=None)


def test_short_app_secret_key_rejected() -> None:
    with pytest.raises(ValueError, match="32 Zeichen"):
        Settings(app_env="test", app_secret_key="zu-kurz", _env_file=None)


def test_config_errors_do_not_leak_secrets(monkeypatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(ValueError, match="APP_SECRET_KEY") as exc_info:
        Settings(app_env="prod", db_password="Geheimes-DB-Passwort", _env_file=None)
    assert "Geheimes-DB-Passwort" not in str(exc_info.value)
