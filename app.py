# app.py
import os
import time
import base64
import datetime as dt
from typing import Optional, List
from datetime import timezone, timedelta

from fastapi import FastAPI, HTTPException, Depends, Query, Response, Header, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware

from pydantic import BaseModel, Field as PydField

from sqlalchemy.exc import IntegrityError
from sqlalchemy import UniqueConstraint, CheckConstraint, Column, Text, Index, and_, or_
from sqlalchemy.sql import func

from sqlmodel import SQLModel, Field, Session, create_engine, select
from sqladmin import Admin, ModelView

# Giả định file security.py tồn tại và có các hàm cần thiết
from security import load_keys_from_env, kid_from_pub, sign_token, verify_token

# ==== Cấu hình Thời gian: UTC là tiêu chuẩn cho backend ====
try:
    from zoneinfo import ZoneInfo
    LOCAL_TZ = ZoneInfo("Asia/Bangkok")
except ImportError:
    LOCAL_TZ = timezone(timedelta(hours=7))

def utc_now() -> dt.datetime:
    """Trả về datetime tz-aware hiện tại ở múi giờ UTC."""
    return dt.datetime.now(timezone.utc)

def to_iso_utc(d: Optional[dt.datetime]) -> Optional[str]:
    """Chuyển datetime (được cho là UTC) sang chuỗi ISO 8601 với 'Z'."""
    if not d:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    else:
        d = d.astimezone(timezone.utc)
    return d.isoformat().replace('+00:00', 'Z')

def to_iso_local_from_utc(d: Optional[dt.datetime]) -> Optional[str]:
    """Chuyển datetime UTC từ DB sang chuỗi ISO 8601 có offset +07:00 để hiển thị."""
    if not d:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(LOCAL_TZ).isoformat()

# ============ Download redirect config ============
GITHUB_OWNER = os.getenv("GITHUB_OWNER", "ISunDevIl")
GITHUB_REPO  = os.getenv("GITHUB_REPO",  "TKT_Files_Tools")
GITHUB_ASSET = os.getenv("GITHUB_ASSET", "TKTApp_Installer.exe")

def _gh_latest_asset_url(owner: str, repo: str, asset: str) -> str:
    return f"https://github.com/{owner}/{repo}/releases/latest/download/{asset}"

def _gh_tag_asset_url(owner: str, repo: str, tag: str, asset: str) -> str:
    return f"https://github.com/{owner}/{repo}/releases/download/{tag}/{asset}"

# ================== Config ==================
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "change-me")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data.db")

# ================== DB ==================
engine = create_engine(DATABASE_URL, echo=False, pool_pre_ping=True)

def get_session():
    with Session(engine) as s:
        yield s

# ================== Models ==================
# Sử dụng UTC cho tất cả các trường datetime trong DB
class License(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    key: str = Field(index=True, unique=True, nullable=False, max_length=64)
    license: Optional[str] = Field(default=None, sa_column=Column(Text))
    status: str = Field(default="active", max_length=16)
    plan: Optional[str] = Field(default=None, max_length=32)
    max_version: Optional[str] = Field(default="0.0.1", max_length=50)
    max_devices: int = Field(default=1)
    expires_at: Optional[dt.datetime] = Field(default=None)
    notes: Optional[str] = Field(default=None)
    created_at: dt.datetime = Field(default_factory=utc_now, index=True)
    updated_at: dt.datetime = Field(default_factory=utc_now, index=True)

    __table_args__ = (
        CheckConstraint("status in ('active','revoked','deleted')", name="ck_license_status"),
        Index("ix_license_created_at", "created_at"),
        Index("ix_license_updated_at", "updated_at"),
    )

class Device(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    license_id: int = Field(index=True, foreign_key="license.id")
    hwid: str = Field(index=True)
    hostname: Optional[str] = None
    platform: Optional[str] = None
    app_ver: Optional[str] = None
    created_at: dt.datetime = Field(default_factory=utc_now, index=True)
    last_seen_at: Optional[dt.datetime] = None
    __table_args__ = (UniqueConstraint("license_id", "hwid", name="uq_device_license_hwid"),)

class DownloadLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    path: str = Field(index=True, max_length=255)
    ua: Optional[str] = Field(default=None)
    ip: Optional[str] = Field(default=None)
    ref: Optional[str] = Field(default=None)
    created_at: dt.datetime = Field(default_factory=utc_now, index=True)

# ================== Auth ==================
bearer = HTTPBearer(auto_error=False)
def admin_auth(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
    x_admin_token: str | None = Header(None, alias="X-Admin-Token")
):
    token = creds.credentials if creds else None
    if not token and x_admin_token:
        token = x_admin_token.strip()
    if not token or token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return True

# ================== Keys ==================
PRIV = None
PUB_PEM = None
KID = None

# ================== Helpers ==================
def _parse_semver(s: Optional[str]) -> tuple[int, int, int]:
    if not s: return (0, 0, 0)
    parts = (s or "").strip().split(".")
    out: List[int] = []
    for i in range(3):
        try:
            out.append(int(parts[i]) if i < len(parts) and parts[i] != "" else 0)
        except (ValueError, IndexError):
            out.append(0)
    return tuple(out)  # type: ignore[return-value]

def _version_lte(a: Optional[str], b: Optional[str]) -> bool:
    return _parse_semver(a) <= _parse_semver(b)

def scalar_int(db: Session, stmt) -> int:
    res = db.exec(stmt).scalar_one_or_none()
    return int(res or 0)

def _public_license_dict(lic: License, db: Session, app_ver: Optional[str] = None) -> dict:
    expired = bool(lic.expires_at and lic.expires_at.replace(tzinfo=timezone.utc) < utc_now())
    used_devices_count = scalar_int(db, select(func.count(Device.id)).where(Device.license_id == lic.id))
    resp = {
        "key": lic.key,
        "status": lic.status,
        "plan": lic.plan,
        "max_devices": lic.max_devices,
        "used_devices": used_devices_count,
        "max_version": lic.max_version,
        "expires_at": to_iso_local_from_utc(lic.expires_at),
        "license": lic.license,
        "kid": KID,
        "now": int(time.time()),
        "expired": expired,
    }
    if app_ver is not None and lic.max_version:
        resp["app_ver"] = app_ver
        resp["app_allowed"] = _version_lte(app_ver, lic.max_version)
    return resp

def _client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else ""

# ================== App ==================
BOOT_TS = time.time()
app = FastAPI(title="TKT License Server", version="1.1.0")

# ---- SQLAdmin & middleware bảo vệ /admin ----
class AdminAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if request.url.path.startswith("/admin"):
            token_ok = False
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ", 1)[1].strip()
                if token == ADMIN_TOKEN:
                    token_ok = True
            
            if not token_ok:
                 return Response("Unauthorized", status_code=401, headers={"WWW-Authenticate": "Bearer"})

        return await call_next(request)

# app.add_middleware(AdminAuthMiddleware) # Bật khi cần bảo vệ /admin
admin = Admin(app, engine)

class LicenseAdmin(ModelView, model=License):
    column_list = [License.id, License.key, License.status, License.plan, License.max_devices, License.expires_at, License.notes, License.updated_at]
    column_searchable_list = [License.key, License.notes, License.plan]
    column_sortable_list = [License.id, License.key, License.status, License.plan, License.expires_at, License.updated_at]

class DeviceAdmin(ModelView, model=Device):
    column_list = [Device.id, Device.license_id, Device.hwid, Device.hostname, Device.last_seen_at]
    column_searchable_list = [Device.hwid, Device.hostname]

admin.add_view(LicenseAdmin)
admin.add_view(DeviceAdmin)

# ================== Lifecycle & Static ==================
@app.on_event("startup")
def startup():
    global PRIV, PUB_PEM, KID
    SQLModel.metadata.create_all(engine)
    PRIV, PUB_PEM = load_keys_from_env()
    KID = kid_from_pub(PUB_PEM)

@app.get("/health", tags=["System"])
def health():
    return {"ok": True, "kid": KID, "timestamp_utc": utc_now().isoformat()}

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def index():
    return """
    <!doctype html><html><head><title>TKT API</title>
    <style>body{font-family: sans-serif; max-width: 800px; margin: 2em auto; padding: 1em; line-height: 1.6;}</style>
    </head><body><h1>✅ TKT FastAPI is running</h1>
    <p>API documentation is available at <a href="/docs">/docs</a>.</p>
    </body></html>
    """

# ================== Schemas ==================
class LicenseCreate(BaseModel):
    key: Optional[str] = None
    license: Optional[str] = None
    plan: Optional[str] = None
    max_devices: int = PydField(default=1, ge=1)
    max_version: Optional[str] = None
    expires_at: Optional[dt.datetime] = None
    notes: Optional[str] = None

class LicenseUpdate(BaseModel):
    status: Optional[str] = None
    plan: Optional[str] = None
    max_devices: Optional[int] = PydField(default=None, ge=1)
    max_version: Optional[str] = None
    expires_at: Optional[dt.datetime] = None
    notes: Optional[str] = None

class LicenseItem(BaseModel):
    id: int
    key: str
    status: str
    plan: Optional[str] = None
    max_devices: int
    used_devices: int
    max_version: Optional[str] = None
    expires_at: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    notes: Optional[str] = None

class LicenseListResponse(BaseModel):
    items: List[LicenseItem]
    total: int
    page: int
    page_size: int
    pages: int

# ================== Admin CRUD ==================
ALLOWED_PLANS = {"Free", "Plus", "Pro"}
def generate_short_key(prefix: str = "TKT", blocks: int = 4, block_size: int = 4) -> str:
    raw_bytes = os.urandom(10)
    key_body = base64.b32encode(raw_bytes).decode('ascii').rstrip("=")
    chunks = [key_body[i:i+block_size] for i in range(0, len(key_body), block_size)]
    return f"{prefix}-" + "-".join(chunks[:blocks])

@app.post("/licenses", tags=["Admin"], dependencies=[Depends(admin_auth)])
def create_license(data: LicenseCreate, db: Session = Depends(get_session)):
    if data.plan and data.plan not in ALLOWED_PLANS:
        raise HTTPException(status_code=422, detail=f"plan must be one of {sorted(ALLOWED_PLANS)}")

    key = data.key or generate_short_key()
    if db.exec(select(License).where(License.key == key)).first():
        raise HTTPException(status_code=409, detail=f"Key '{key}' already exists.")

    lic = License.model_validate(data)
    lic.key = key # Ensure the generated or provided key is set
    
    try:
        db.add(lic)
        db.commit()
        db.refresh(lic)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database save error: {e}")

    return lic

@app.get("/licenses", response_model=LicenseListResponse, tags=["Admin"], dependencies=[Depends(admin_auth)])
def list_licenses(
    db: Session = Depends(get_session),
    q: Optional[str] = Query(None, description="Search by key, plan, or notes"),
    status: Optional[str] = Query(None, description="Filter by status: active/revoked/deleted"),
    plan: Optional[str] = Query(None, description="Filter by plan: Free/Plus/Pro"),
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    sort_by: str = Query("created_at", pattern="^(created_at|updated_at|expires_at|key)$"),
    sort_dir: str = Query("desc", pattern="^(asc|desc)$"),
):
    filters = []
    if q:
        like_query = f"%{q}%"
        filters.append(or_(License.key.ilike(like_query), License.plan.ilike(like_query), License.notes.ilike(like_query)))
    if status:
        filters.append(License.status == status)
    if plan:
        filters.append(License.plan == plan)
    
    where_clause = and_(*filters)
    
    count_stmt = select(func.count(License.id)).where(where_clause)
    total = scalar_int(db, count_stmt)
    
    sort_map = {"created_at": License.created_at, "updated_at": License.updated_at, "expires_at": License.expires_at, "key": License.key}
    order_col = sort_map.get(sort_by, License.created_at)
    order_by = order_col.desc() if sort_dir == "desc" else order_col.asc()
    
    offset = (page - 1) * page_size
    stmt = select(License).where(where_clause).order_by(order_by).offset(offset).limit(page_size)
    licenses = db.exec(stmt).all()
    
    counts = {}
    if licenses:
        lic_ids = [lic.id for lic in licenses]
        cnt_stmt = select(Device.license_id, func.count(Device.id)).where(Device.license_id.in_(lic_ids)).group_by(Device.license_id)
        counts = dict(db.exec(cnt_stmt).all())
        
    items = [
        LicenseItem(
            id=lic.id,
            key=lic.key,
            status=lic.status,
            plan=lic.plan,
            max_devices=lic.max_devices,
            used_devices=counts.get(lic.id, 0),
            max_version=lic.max_version,
            expires_at=to_iso_local_from_utc(lic.expires_at),
            created_at=to_iso_local_from_utc(lic.created_at),
            updated_at=to_iso_local_from_utc(lic.updated_at),
            notes=lic.notes
        ) for lic in licenses
    ]
    
    pages = (total + page_size - 1) // page_size
    return {"items": items, "total": total, "page": page, "page_size": page_size, "pages": pages}

@app.patch("/licenses/{key}", tags=["Admin"], dependencies=[Depends(admin_auth)])
def update_license(key: str, data: LicenseUpdate, db: Session = Depends(get_session)):
    lic = db.exec(select(License).where(License.key == key)).first()
    if not lic:
        raise HTTPException(status_code=404, detail="License not found")

    update_data = data.model_dump(exclude_unset=True)
    
    for k, v in update_data.items():
        setattr(lic, k, v)

    lic.updated_at = utc_now()
    db.add(lic)
    db.commit()
    db.refresh(lic)
    return lic

@app.delete("/licenses/{key}", tags=["Admin"], dependencies=[Depends(admin_auth)])
def delete_license(key: str, db: Session = Depends(get_session)):
    lic = db.exec(select(License).where(License.key == key)).first()
    if not lic:
        raise HTTPException(status_code=404, detail="License not found")
    lic.status = "deleted"
    lic.updated_at = utc_now()
    db.add(lic)
    db.commit()
    return {"ok": True, "status": "deleted"}

@app.post("/revoke/{key}", tags=["Admin"], dependencies=[Depends(admin_auth)])
def revoke_license(key: str, db: Session = Depends(get_session)):
    lic = db.exec(select(License).where(License.key == key)).first()
    if not lic:
        raise HTTPException(status_code=404, detail="License not found")
    lic.status = "revoked"
    lic.updated_at = utc_now()
    db.add(lic)
    db.commit()
    return {"ok": True, "status": "revoked"}

# ================== Public Endpoints ==================
class ActivateIn(BaseModel):
    key: str
    hwid: str
    app_ver: Optional[str] = None
    hostname: Optional[str] = None
    platform: Optional[str] = None

@app.post("/activate", tags=["Public"])
def activate(data: ActivateIn, db: Session = Depends(get_session)):
    lic = db.exec(select(License).where(License.key == data.key)).first()
    if not lic or lic.status != "active":
        raise HTTPException(status_code=403, detail="License is invalid or not active.")
    if lic.expires_at and lic.expires_at.replace(tzinfo=timezone.utc) < utc_now():
        raise HTTPException(status_code=403, detail="License has expired.")

    device = db.exec(select(Device).where(Device.license_id == lic.id, Device.hwid == data.hwid)).first()
    
    if not device:
        # New device, check seat count
        used_seats = scalar_int(db, select(func.count(Device.id)).where(Device.license_id == lic.id))
        if used_seats >= lic.max_devices:
            raise HTTPException(status_code=403, detail=f"All available seats ({lic.max_devices}) for this license are in use.")
        
        device = Device(
            license_id=lic.id,
            hwid=data.hwid,
            hostname=data.hostname,
            platform=data.platform,
            app_ver=data.app_ver,
            last_seen_at=utc_now()
        )
        db.add(device)
    else:
        # Existing device, update its info
        device.hostname = data.hostname
        device.platform = data.platform
        device.app_ver = data.app_ver
        device.last_seen_at = utc_now()
        db.add(device)
        
    db.commit()
    return _public_license_dict(lic, db, data.app_ver)


@app.get("/download/myapp", tags=["Download"], response_class=RedirectResponse)
def download_latest(request: Request, db: Session = Depends(get_session)):
    """Redirects to the latest release asset on GitHub."""
    url = _gh_latest_asset_url(GITHUB_OWNER, GITHUB_REPO, GITHUB_ASSET)
    
    try:
        log_entry = DownloadLog(
            path="/download/myapp",
            ua=request.headers.get("User-Agent"),
            ip=_client_ip(request),
            ref=request.headers.get("Referer")
        )
        db.add(log_entry)
        db.commit()
    except Exception:
        db.rollback() # Don't block download if logging fails

    return RedirectResponse(url, status_code=307) # Use 307 to preserve method