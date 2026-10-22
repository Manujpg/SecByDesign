"""Zentrale Konfiguration.

Alle Werte kommen aus Umgebungsvariablen (im Cluster aus ConfigMap und Secrets).
Es gibt bewusst keine Default-Passwörter oder -Schlüssel: Im Betrieb (APP_ENV=prod)
startet die Anwendung nicht, wenn Zugangsdaten fehlen (SR-06 Secret-Hygiene).
"""

from __future__ import annotations

import os
import re
from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import URL, make_url

_ROLE_NAME = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
_ORIGIN = re.compile(r"^https?://[a-z0-9.\-]+(:\d{1,5})?$")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        secrets_dir=None,
        # Validierungsfehler dürfen keine Eingabewerte zeigen: sonst landen beim Start mit
        # unvollständiger Konfiguration Passwörter im Container-Log (SR-05, SR-06).
        hide_input_in_errors=True,
    )

    # Sicherer Default: ohne Angabe läuft die App im Produktionsmodus.
    app_env: Literal["dev", "test", "prod"] = "prod"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # ---- Datenbank -----------------------------------------------------------
    db_host: str = "localhost"
    db_port: int = Field(default=5432, ge=1, le=65535)
    db_name: str = "praxistermin"
    db_user: str = "praxis_app"
    db_password: SecretStr | None = None
    db_sslmode: Literal["disable", "prefer", "require", "verify-full"] = "prefer"
    database_url: SecretStr | None = None
    db_app_role: str = "praxis_app"

    # ---- Anwendungsschlüssel --------------------------------------------------
    # Server-Geheimnis (Kubernetes-Secret app-session-key). Verwendet für HMAC von
    # Login-Kennungen im Audit-Log und ab M4 für die Verschlüsselung der TOTP-Secrets.
    app_secret_key: SecretStr | None = None

    # ---- CSRF: erlaubte Origins für zustandsändernde Requests (kommagetrennt) --
    allowed_origins: str = "https://localhost"

    # ---- Sitzungen (SR-07) ---------------------------------------------------
    session_idle_minutes: int = Field(default=30, ge=5, le=240)
    session_absolute_hours: int = Field(default=8, ge=1, le=24)
    mfa_pending_minutes: int = Field(default=5, ge=1, le=15)

    # ---- MFA (SR-02) ----------------------------------------------------------
    mfa_issuer: str = Field(default="Ärztehaus Lindle", min_length=1, max_length=64)
    # Falsche Codes pro Anmeldung, danach wird die halb angemeldete Sitzung verworfen.
    mfa_max_failures: int = Field(default=5, ge=1, le=20)

    # ---- Brute-Force-Schutz (SR-08) -----------------------------------------
    login_max_failures: int = Field(default=10, ge=3, le=50)
    login_window_minutes: int = Field(default=15, ge=1, le=120)
    login_ip_max_failures: int = Field(default=30, ge=5, le=500)
    register_ip_max: int = Field(default=10, ge=1, le=500)

    # ---- Passwort-Hashing (SR-01): Argon2id ----------------------------------
    argon2_time_cost: int = Field(default=3, ge=1)
    argon2_memory_cost_kib: int = Field(default=65536, ge=1024)
    argon2_parallelism: int = Field(default=4, ge=1)

    # ---- Admin-Bootstrap -----------------------------------------------------
    # Wird beim ersten Start genau einmal angelegt, wenn noch keine Nutzer:innen existieren.
    admin_bootstrap_email: str = "admin@aerztehaus-lindle.de"
    admin_bootstrap_password: SecretStr | None = None

    @field_validator("db_app_role")
    @classmethod
    def _valid_role_name(cls, value: str) -> str:
        if not _ROLE_NAME.fullmatch(value):
            raise ValueError("ungültiger Rollenname")
        return value

    @field_validator("allowed_origins")
    @classmethod
    def _valid_origins(cls, value: str) -> str:
        origins = [o.strip().lower() for o in value.split(",") if o.strip()]
        if not origins or not all(_ORIGIN.fullmatch(o) for o in origins):
            raise ValueError("ALLOWED_ORIGINS muss eine kommagetrennte Liste von Origins sein")
        return ",".join(origins)

    @field_validator("admin_bootstrap_email")
    @classmethod
    def _lower_email(cls, value: str) -> str:
        return value.strip().lower()

    @model_validator(mode="after")
    def _require_secrets_in_prod(self) -> Settings:
        if self.app_env == "prod":
            if self.database_url is not None:
                raise ValueError("DATABASE_URL ist im Produktionsmodus nicht erlaubt")
            if self.db_password is None or not self.db_password.get_secret_value():
                raise ValueError("DB_PASSWORD muss im Produktionsmodus gesetzt sein")
            if self.app_secret_key is None:
                raise ValueError("APP_SECRET_KEY muss im Produktionsmodus gesetzt sein")
        if self.app_secret_key is not None and len(self.app_secret_key.get_secret_value()) < 32:
            raise ValueError("APP_SECRET_KEY muss mindestens 32 Zeichen lang sein")
        if (
            self.admin_bootstrap_password is not None
            and len(self.admin_bootstrap_password.get_secret_value()) < 16
        ):
            raise ValueError("ADMIN_BOOTSTRAP_PASSWORD muss mindestens 16 Zeichen lang sein")
        return self

    @property
    def is_dev(self) -> bool:
        return self.app_env == "dev"

    @property
    def origin_allowlist(self) -> frozenset[str]:
        return frozenset(self.allowed_origins.split(","))

    def secret_key_bytes(self) -> bytes:
        """Server-Schlüssel; in dev/test ohne Angabe ein fester, nur lokal gültiger Wert."""
        if self.app_secret_key is not None:
            return self.app_secret_key.get_secret_value().encode()
        if self.app_env == "prod":  # durch den Validator ausgeschlossen, doppelt hält besser
            raise RuntimeError("APP_SECRET_KEY fehlt")
        return b"nur-fuer-lokale-entwicklung-und-tests-nicht-produktiv"

    def sqlalchemy_url(self) -> URL:
        """Baut die Verbindungs-URL, ohne das Passwort je als String zu loggen."""
        if self.database_url is not None:
            return make_url(self.database_url.get_secret_value())
        return URL.create(
            drivername="postgresql+psycopg",
            username=self.db_user,
            password=self.db_password.get_secret_value() if self.db_password else None,
            host=self.db_host,
            port=self.db_port,
            database=self.db_name,
            query={"sslmode": self.db_sslmode},
        )


@lru_cache
def get_settings() -> Settings:
    # SETTINGS_ENV_FILE="" schaltet das Einlesen von .env ab (Tests, Container).
    env_file = os.environ.get("SETTINGS_ENV_FILE", ".env") or None
    return Settings(_env_file=env_file)
