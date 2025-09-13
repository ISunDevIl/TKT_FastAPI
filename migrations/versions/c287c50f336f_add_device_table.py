"""add device table

Revision ID: c287c50f336f
Revises: 92c6d9b78485
Create Date: 2025-09-13 12:34:56.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "c287c50f336f"
down_revision: Union[str, Sequence[str], None] = "92c6d9b78485"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Tạo bảng device
    op.create_table(
        "device",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("license_id", sa.Integer(), nullable=False),
        sa.Column("hwid", sa.String(length=255), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("platform", sa.String(length=50), nullable=True),
        sa.Column("app_ver", sa.String(length=50), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("last_seen_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(
            ["license_id"],
            ["license.id"],
            name="fk_device_license_id",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("license_id", "hwid", name="uq_device_license_hwid"),
    )

    # Indexes
    op.create_index("ix_device_license_id", "device", ["license_id"], unique=False)
    op.create_index("ix_device_hwid", "device", ["hwid"], unique=False)
    op.create_index("ix_device_created_at", "device", ["created_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_device_created_at", table_name="device")
    op.drop_index("ix_device_hwid", table_name="device")
    op.drop_index("ix_device_license_id", table_name="device")
    op.drop_table("device")
