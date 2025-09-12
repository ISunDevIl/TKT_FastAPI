from typing import Optional
from sqlmodel import SQLModel, Field
from sqlalchemy import UniqueConstraint, CheckConstraint
import datetime

class License(SQLModel, table=True):
    # Bảng license
    id: Optional[int] = Field(default=None, primary_key=True)
    key: str = Field(index=True, unique=True, nullable=False)     # key ngắn (TKT-XXXX-XXXX)
    license: Optional[str] = None                                 # (tuỳ chọn) lưu chuỗi license đầy đủ nếu cần
    plan: Optional[str] = None
    expires_at: Optional[datetime.datetime] = None                # ngày hết hạn (UTC)
    max_version: str = Field(default="0.0.1")                     # phiên bản tối đa
    max_devices: int = Field(default=1)                           # số thiết bị tối đa
    status: str = Field(default="active")                         # active|revoked|deleted
    notes: Optional[str] = None
    created_at: datetime.datetime = Field(default_factory=datetime.datetime.utcnow, index=True)
    updated_at: datetime.datetime = Field(default_factory=datetime.datetime.utcnow, index=True)

    __table_args__ = (
        CheckConstraint("status in ('active','revoked','deleted')", name="ck_license_status"),
    )

class Device(SQLModel, table=True):
    # Bảng quản lý máy sử dụng license
    id: Optional[int] = Field(default=None, primary_key=True)
    license_id: int = Field(index=True, foreign_key="license.id") # tham chiếu license
    hwid: str = Field(index=True)                                 # mã phần cứng duy nhất
    hostname: Optional[str] = None                                # tên máy (tuỳ chọn)
    platform: Optional[str] = None                                # Windows/Linux/Mac...
    app_ver: Optional[str] = None                                 # version app khi activate
    created_at: datetime.datetime = Field(default_factory=datetime.datetime.utcnow, index=True)
    last_seen_at: Optional[datetime.datetime] = None

    __table_args__ = (
        UniqueConstraint("license_id", "hwid", name="uq_device_license_hwid"),
    )
