"""Alembic-Umgebung.

Im Cluster läuft ``alembic upgrade head`` im Init-Container mit dem Konto
``praxis_migrate`` (DDL-Rechte). Die laufende Anwendung nutzt ``praxis_app``
(nur DML). Beide Konten bekommen ihre Zugangsdaten über dieselben Variablen
DB_USER / DB_PASSWORD, aber aus unterschiedlichen Secrets.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, pool

from app.core.config import get_settings
from app.models import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata
settings = get_settings()

# Für Migrationen, die Rechte der Laufzeit-Rolle anpassen (z. B. audit_log append-only).
config.attributes.setdefault("app_role", settings.db_app_role)


def run_migrations_offline() -> None:
    context.configure(
        url=settings.sqlalchemy_url().render_as_string(hide_password=True),
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(settings.sqlalchemy_url(), poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            render_as_batch=connection.dialect.name == "sqlite",
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
