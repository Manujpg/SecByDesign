"""Zentrale Konfiguration.

Alle Werte kommen aus Umgebungsvariablen (im Cluster aus ConfigMap und Secrets).
Es gibt bewusst keine Default-Passwörter: Im Betrieb (APP_ENV=prod) startet die
Anwendung nicht, wenn Zugangsdaten fehlen (SR-06 Secret-Hygiene).
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import URL, make_url

_ROLE_NAME = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        # Optional: Secrets als Dateien (z. B. gemountetes Kubernetes-Secret).
        secrets_dir=None,
    )

    # Sicherer Default: ohne Angabe läuft die App im Produktionsmodus.
    app_env: Literal["dev", "test", "prod"] = "prod"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # Datenbank: entweder Einzelwerte oder eine vollständige URL (nur dev/test).
    db_host: str = "localhost"
    db_port: int = Field(default=5432, ge=1, le=65535)
    db_name: str = "praxistermin"
    db_user: str = "praxis_app"
    db_password: SecretStr | None = None
    db_sslmode: Literal["disable", "prefer", "require", "verify-full"] = "prefer"
    database_url: SecretStr | None = None

    # Name der Laufzeit-Rolle, der die Migration Rechte entzieht (audit_log append-only).
    db_app_role: str = "praxis_app"

    @field_validator("db_app_role")
    @classmethod
    def _valid_role_name(cls, value: str) -> str:
        if not _ROLE_NAME.fullmatch(value):
            raise ValueError("ungültiger Rollenname")
        return value

    @model_validator(mode="after")
    def _require_credentials_in_prod(self) -> Settings:
        if self.app_env == "prod":
            if self.database_url is not None:
                raise ValueError("DATABASE_URL ist im Produktionsmodus nicht erlaubt")
            if self.db_password is None or not self.db_password.get_secret_value():
                raise ValueError("DB_PASSWORD muss im Produktionsmodus gesetzt sein")
        return self

    @property
    def is_dev(self) -> bool:
        return self.app_env == "dev"

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
    return Settings()
