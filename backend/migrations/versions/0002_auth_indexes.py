"""Indizes für Rate-Limiting und Audit-Abfragen (M3)

Das Rate-Limiting beim Login zählt Fehlversuche im Audit-Log pro IP und pro
E-Mail-Kennung in einem Zeitfenster. Diese Indizes halten die Abfragen schnell.

Revision ID: 0002
Revises: 0001
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index("ix_audit_log_action_ip_ts", "audit_log", ["action", "ip", "ts"])
    op.create_index("ix_audit_log_action_target_ts", "audit_log", ["action", "target_id", "ts"])
    op.create_index("ix_sessions_expires_at", "sessions", ["expires_at"])


def downgrade() -> None:
    op.drop_index("ix_sessions_expires_at", table_name="sessions")
    op.drop_index("ix_audit_log_action_target_ts", table_name="audit_log")
    op.drop_index("ix_audit_log_action_ip_ts", table_name="audit_log")
