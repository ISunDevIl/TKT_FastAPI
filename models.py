from sqlmodel import SQLModel, Field
from typing import Optional
import datetime

class License(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    key: str = Field(index=True, unique=True, nullable=False)
    status: str = Field(default="active")  # active|revoked|deleted
    plan: Optional[str] = None
    max_devices: int = 1
    expires_at: Optional[datetime.datetime] = None
    notes: Optional[str] = None
    created_at: datetime.datetime = Field(default_factory=datetime.datetime.utcnow)
    updated_at: datetime.datetime = Field(default_factory=datetime.datetime.utcnow)

class Activation(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    license_key: str = Field(index=True)
    hwid: str
    created_at: datetime.datetime = Field(default_factory=datetime.datetime.utcnow)
    last_seen_at: Optional[datetime.datetime] = None
