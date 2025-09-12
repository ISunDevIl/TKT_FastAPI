"""add license & max_version & timestamps to License

Revision ID: 92c6d9b78485
Revises: bfbe0f25fa33
Create Date: 2025-09-12 09:34:25.857572
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision: str = "92c6d9b78485"
down_revision: Union[str, Sequence[str], None] = "bfbe0f25fa33"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""

    # 1) Đổi kiểu status: ENUM('active','revoked','deleted') -> VARCHAR(16)
    #    (giữ nguyên dữ liệu hiện có)
    op.alter_column(
        "license",
        "status",
        existing_type=mysql.ENUM("active", "revoked", "deleted"),
        type_=sa.String(length=16),
        existing_nullable=False,
        server_default=None,  # bỏ default trên DB nếu có, để dùng logic app
    )

    # 2) Thêm các cột mới
    op.add_column("license", sa.Column("license", sa.Text(), nullable=True))
    op.add_column(
        "license",
        sa.Column(
            "max_version", sa.String(length=50), nullable=False, server_default="0.0.1"
        ),
    )
    op.add_column(
        "license",
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
    )
    op.add_column(
        "license",
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
    )

    # 3) Thiết lập ON UPDATE CURRENT_TIMESTAMP cho updated_at (MySQL-specific)
    op.execute(
        "ALTER TABLE `license` "
        "MODIFY `updated_at` DATETIME NOT NULL "
        "DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"
    )

    # 4) Tạo index cho created_at và updated_at
    op.create_index("ix_license_created_at", "license", ["created_at"], unique=False)
    op.create_index("ix_license_updated_at", "license", ["updated_at"], unique=False)
    op.create_index("ix_activation_created_at", "activation", ["created_at"], unique=False)

    # (Tuỳ chọn) Bỏ server_default của max_version nếu muốn chỉ giữ default ở tầng app
    # op.alter_column("license", "max_version", server_default=None)


def downgrade() -> None:
    """Downgrade schema."""
    # Xoá index
    op.drop_index("ix_license_updated_at", table_name="license")
    op.drop_index("ix_license_created_at", table_name="license")

    # Xoá các cột đã thêm
    op.drop_column("license", "updated_at")
    op.drop_column("license", "created_at")
    op.drop_column("license", "max_version")
    op.drop_column("license", "license")

    # Đổi kiểu status trở lại ENUM (kèm default 'active' như schema cũ nếu cần)
    op.alter_column(
        "license",
        "status",
        existing_type=sa.String(length=16),
        type_=mysql.ENUM("active", "revoked", "deleted"),
        existing_nullable=False,
        server_default=sa.text("'active'"),
    )