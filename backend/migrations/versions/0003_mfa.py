"""MFA: Replay-Schutz für TOTP und eindeutige Recovery-Codes (M4)

Revision ID: 0003
Revises: 0002
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("mfa_last_used_step", sa.BigInteger(), nullable=True))
    op.create_unique_constraint(
        "uq_recovery_codes_user_code", "recovery_codes", ["user_id", "code_hash"]
    )


def downgrade() -> None:
    op.drop_constraint("uq_recovery_codes_user_code", "recovery_codes", type_="unique")
    op.drop_column("users", "mfa_last_used_step")
