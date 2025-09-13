"""add license & max_version & timestamps to License

Revision ID: 92c6d9b78485
Revises: bfbe0f25fa33
Create Date: 2025-09-12 09:34:25.857572
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision: str = "92c6d9b78485"
down_revision: Union[str, Sequence[str], None] = "bfbe0f25fa33"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# ---------- helpers (idempotent) ----------
def _insp():
    return inspect(op.get_bind())

def _has_column(table: str, column: str) -> bool:
    return any(c["name"] == column for c in _insp().get_columns(table))

def _has_index(table: str, name: str) -> bool:
    return any(ix["name"] == name for ix in _insp().get_indexes(table))

def _dialect() -> str:
    return op.get_bind().dialect.name  # 'mysql', 'postgresql', 'sqlite', ...


def upgrade() -> None:
    """Upgrade schema."""

    # 1) Đổi kiểu status: ENUM('active','revoked','deleted') -> VARCHAR(16)
    #    Bọc try/except để nếu đã đổi trước đó thì bỏ qua.
    try:
        op.alter_column(
            "license",
            "status",
            existing_type=mysql.ENUM("active", "revoked", "deleted"),
            type_=sa.String(length=16),
            existing_nullable=False,
            server_default=None,
        )
    except Exception:
        # Có thể đã là VARCHAR sẵn, bỏ qua
        pass

    # 2) Thêm các cột mới (chỉ thêm nếu chưa tồn tại)
    if not _has_column("license", "license"):
        op.add_column("license", sa.Column("license", sa.Text(), nullable=True))

    if not _has_column("license", "max_version"):
        op.add_column(
            "license",
            sa.Column("max_version", sa.String(length=50), nullable=False, server_default="0.0.1"),
        )

    if not _has_column("license", "created_at"):
        op.add_column(
            "license",
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        )

    if not _has_column("license", "updated_at"):
        op.add_column(
            "license",
            sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        )

    # 3) MySQL-specific: thiết lập ON UPDATE cho updated_at (chỉ khi MySQL & có cột)
    if _dialect() == "mysql" and _has_column("license", "updated_at"):
        op.execute(
            "ALTER TABLE `license` "
            "MODIFY `updated_at` DATETIME NOT NULL "
            "DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"
        )
        # đảm bảo created_at có default CURRENT_TIMESTAMP
        if _has_column("license", "created_at"):
            op.execute(
                "ALTER TABLE `license` "
                "MODIFY `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP"
            )

    # 4) Tạo index (nếu chưa có)
    if _has_column("license", "created_at") and not _has_index("license", "ix_license_created_at"):
        op.create_index("ix_license_created_at", "license", ["created_at"], unique=False)

    if _has_column("license", "updated_at") and not _has_index("license", "ix_license_updated_at"):
        op.create_index("ix_license_updated_at", "license", ["updated_at"], unique=False)

    if not _has_index("activation", "ix_activation_created_at"):
        op.create_index("ix_activation_created_at", "activation", ["created_at"], unique=False)


def downgrade() -> None:
    """Downgrade schema."""

    # Xoá index nếu tồn tại
    if _has_index("activation", "ix_activation_created_at"):
        op.drop_index("ix_activation_created_at", table_name="activation")
    if _has_index("license", "ix_license_updated_at"):
        op.drop_index("ix_license_updated_at", table_name="license")
    if _has_index("license", "ix_license_created_at"):
        op.drop_index("ix_license_created_at", table_name="license")

    # Xoá các cột đã thêm (nếu có)
    if _has_column("license", "updated_at"):
        op.drop_column("license", "updated_at")
    if _has_column("license", "created_at"):
        op.drop_column("license", "created_at")
    if _has_column("license", "max_version"):
        op.drop_column("license", "max_version")
    if _has_column("license", "license"):
        op.drop_column("license", "license")

    # Đổi kiểu status trở lại ENUM (MySQL), nếu có thể
    try:
        op.alter_column(
            "license",
            "status",
            existing_type=sa.String(length=16),
            type_=mysql.ENUM("active", "revoked", "deleted"),
            existing_nullable=False,
            server_default=sa.text("'active'"),
        )
    except Exception:
        # Nếu không phải MySQL/hoặc đã là ENUM rồi, bỏ qua
        pass
