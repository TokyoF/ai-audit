"""add pending and completed to auditstatus

Revision ID: a1b2c3d4e5f6
Revises: b22d8c28bd7c
Create Date: 2026-07-07 00:00:00.000000
"""
from alembic import op

revision = "a1b2c3d4e5f6"
down_revision = "b22d8c28bd7c"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE auditstatus ADD VALUE IF NOT EXISTS 'pending'")
        op.execute("ALTER TYPE auditstatus ADD VALUE IF NOT EXISTS 'completed'")


def downgrade() -> None:
    # Postgres cannot drop enum values without recreating the type; no-op.
    pass
