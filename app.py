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
    __table_args__ = (CheckConstraint("status in ('active','revoked','deleted')", name="ck_license_status"),)

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

class Activation(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    license_key: str = Field(index=True, max_length=64)
    hwid: str = Field(max_length=255)
    created_at: dt.datetime = Field(default_factory=utc_now, index=True)
    last_seen_at: Optional[dt.datetime] = None
    __table_args__ = (UniqueConstraint("license_key", "hwid", name="uq_activation_license_hwid"),)

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
# === SỬA LỖI TẠI ĐÂY ===
def scalar_int(db: Session, stmt) -> int:
    """
    Thực thi một câu lệnh và trả về một giá trị số nguyên duy nhất một cách an toàn.
    """
    row = db.exec(stmt).first()
    if row:
        # Kết quả trả về là một tuple, ví dụ (50,), nên ta lấy phần tử đầu tiên
        return int(row[0])
    return 0

def _parse_semver(s: Optional[str]) -> tuple[int, int, int]:
    if not s: return (0, 0, 0)
    parts = (s or "").strip().split(".")
    out: List[int] = []
    for i in range(3):
        try:
            out.append(int(parts[i]) if i < len(parts) and parts[i] != "" else 0)
        except (ValueError, IndexError):
            out.append(0)
    return tuple(out)

def _version_lte(a: Optional[str], b: Optional[str]) -> bool:
    return _parse_semver(a) <= _parse_semver(b)

def _public_license_dict(lic: License, db: Session, app_ver: Optional[str] = None) -> dict:
    expires_at_utc = lic.expires_at.replace(tzinfo=timezone.utc) if lic.expires_at and lic.expires_at.tzinfo is None else lic.expires_at
    expired = bool(expires_at_utc and expires_at_utc < utc_now())
    used_devices_count = scalar_int(db, select(func.count(Device.id)).where(Device.license_id == lic.id))
    resp = {
        "key": lic.key, "status": lic.status, "plan": lic.plan,
        "max_devices": lic.max_devices, "used_devices": used_devices_count,
        "max_version": lic.max_version, "expires_at": to_iso_local_from_utc(lic.expires_at),
        "license": lic.license, "kid": KID, "now": int(time.time()), "expired": expired,
    }
    if app_ver and lic.max_version:
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

admin = Admin(app, engine)
class LicenseAdmin(ModelView, model=License):
    column_list = [License.id, License.key, License.status, License.plan, License.max_devices, License.expires_at, License.notes, License.updated_at]
    column_searchable_list = [License.key, License.notes, License.plan]

admin.add_view(LicenseAdmin)

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
    return """<!doctype html>
<html lang="vi"><head><meta charset="utf-8"><title>TKT FastAPI</title><style>body{font-family: system-ui, sans-serif;max-width: 720px;margin: 40px auto;line-height: 1.6;color: #333;background-color: #f9f9f9;padding: 20px;}h1{color: #28a745;font-size: 2.5em;margin-bottom: 10px;display: flex;align-items: center;}h1::before{content: "✅ ";margin-right: 10px;}h4{font-style: italic;color: #666;margin-top: 0;margin-bottom: 20px;}p{margin: 10px 0;font-size: 1.1em;}code{background-color: #e9ecef;padding: 2px 6px;border-radius: 4px;font-family: monospace;}ul{list-style-type: none;padding: 0;margin: 20px 0;}li{margin-bottom: 10px;}a{display: inline-block;text-decoration: none;color: #007bff;background-color: #fff;padding: 10px 15px;border: 1px solid #ddd;border-radius: 5px;transition: background-color 0.3s, color 0.3s;}.note{font-size: 0.9em;color: #555;margin-left: 10px;}.container{background-color: #fff;padding: 30px;border-radius: 10px;box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);}</style></head>
<body><div class="container"><h1>TKT FastAPI đang hoạt động</h1><h4>Bỗng nhận ra hương ổi</h4><h4>Phả vào trong gió se</h4><h4>Sương chùng chình qua ngõ</h4><h4>Hình như thu đã về.</h4><ul><li><a href="/docs">/docs</a></li><li><a href="/download">/download</a> <span class="note">(trang tải xuống)</span></li></ul></div></body></html>
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

class ActivateIn(BaseModel):
    key: str
    hwid: str
    app_ver: Optional[str] = None

class ValidateIn(BaseModel):
    token: str
    hwid: str

class DeactivateIn(BaseModel):
    key: str
    hwid: str

class LicenseLookupIn(BaseModel):
    key: str
    app_ver: Optional[str] = None

class LicenseItem(BaseModel):
    id: int; key: str; status: str; plan: Optional[str] = None; max_devices: int
    used_devices: int; max_version: Optional[str] = None; expires_at: Optional[str] = None
    created_at: Optional[str] = None; updated_at: Optional[str] = None; notes: Optional[str] = None

class LicenseListResponse(BaseModel):
    items: List[LicenseItem]; total: int; page: int; page_size: int; pages: int

class DeviceRegisterIn(BaseModel):
    key: str; hwid: str; hostname: Optional[str] = None; platform: Optional[str] = None; app_ver: Optional[str] = None

# ================== Admin CRUD ==================
ALLOWED_PLANS = {"Free", "Plus", "Pro"}
def generate_short_key(prefix: str = "TKT", blocks: int = 4, block_size: int = 4) -> str:
    raw_bytes = os.urandom(10); key_body = base64.b32encode(raw_bytes).decode('ascii').rstrip("=")
    chunks = [key_body[i:i+block_size] for i in range(0, len(key_body), block_size)]
    return f"{prefix}-" + "-".join(chunks[:blocks])

@app.post("/licenses", tags=["Admin"], dependencies=[Depends(admin_auth)])
def create_license(data: LicenseCreate, db: Session = Depends(get_session)):
    if data.plan and data.plan not in ALLOWED_PLANS:
        raise HTTPException(status_code=422, detail=f"Plan must be one of {sorted(ALLOWED_PLANS)}")
    key = data.key or generate_short_key()
    if db.exec(select(License).where(License.key == key)).first():
        raise HTTPException(status_code=409, detail=f"Key '{key}' already exists.")
    
    lic = License.model_validate(data)
    lic.key = key
    try:
        db.add(lic); db.commit(); db.refresh(lic)
    except Exception as e:
        db.rollback(); raise HTTPException(status_code=500, detail=f"Database error: {e}")
    return lic

@app.get("/licenses", response_model=LicenseListResponse, tags=["Admin"], dependencies=[Depends(admin_auth)])
def list_licenses(
    db: Session = Depends(get_session), q: Optional[str] = Query(None),
    status: Optional[str] = Query(None), plan: Optional[str] = Query(None),
    page: int = Query(1, ge=1), page_size: int = Query(10, ge=1, le=100),
    sort_by: str = Query("created_at", pattern="^(created_at|updated_at|expires_at|key)$"),
    sort_dir: str = Query("desc", pattern="^(asc|desc)$"),
):
    filters = []
    if q: filters.append(or_(License.key.ilike(f"%{q}%"), License.plan.ilike(f"%{q}%"), License.notes.ilike(f"%{q}%")))
    if status: filters.append(License.status == status)
    if plan: filters.append(License.plan == plan)
    where_clause = and_(*filters)
    
    count_stmt = select(func.count(License.id)).where(where_clause)
    total = scalar_int(db, count_stmt)
    
    sort_map = {"created_at": License.created_at, "updated_at": License.updated_at, "expires_at": License.expires_at, "key": License.key}
    order_col = sort_map.get(sort_by, License.created_at)
    order_by = order_col.desc() if sort_dir == "desc" else order_col.asc()
    offset = (page - 1) * page_size
    licenses = db.exec(select(License).where(where_clause).order_by(order_by).offset(offset).limit(page_size)).all()
    
    counts = {}
    if licenses:
        lic_ids = [lic.id for lic in licenses]
        cnt_stmt = select(Device.license_id, func.count(Device.id)).where(Device.license_id.in_(lic_ids)).group_by(Device.license_id)
        counts = dict(db.exec(cnt_stmt).all())
        
    items = [LicenseItem(id=lic.id, key=lic.key, status=lic.status, plan=lic.plan,
        max_devices=lic.max_devices, used_devices=counts.get(lic.id, 0),
        max_version=lic.max_version, expires_at=to_iso_local_from_utc(lic.expires_at),
        created_at=to_iso_local_from_utc(lic.created_at), updated_at=to_iso_local_from_utc(lic.updated_at),
        notes=lic.notes) for lic in licenses]
    
    pages = (total + page_size - 1) // page_size
    return {"items": items, "total": total, "page": page, "page_size": page_size, "pages": pages}

@app.patch("/licenses/{key}", tags=["Admin"], dependencies=[Depends(admin_auth)])
def update_license(key: str, data: LicenseUpdate, db: Session = Depends(get_session)):
    lic = db.exec(select(License).where(License.key == key)).first()
    if not lic: raise HTTPException(status_code=404, detail="License not found")
    update_data = data.model_dump(exclude_unset=True)
    for k, v in update_data.items():
        setattr(lic, k, v)
    lic.updated_at = utc_now()
    db.add(lic); db.commit(); db.refresh(lic)
    return lic

@app.delete("/licenses/{key}", tags=["Admin"], dependencies=[Depends(admin_auth)])
def delete_license(key: str, db: Session = Depends(get_session)):
    lic = db.exec(select(License).where(License.key == key)).first()
    if not lic: raise HTTPException(status_code=404, detail="License not found")
    lic.status = "deleted"; lic.updated_at = utc_now(); db.add(lic); db.commit()
    return {"ok": True, "status": "deleted"}

@app.post("/revoke/{key}", tags=["Admin"], dependencies=[Depends(admin_auth)])
def revoke_license(key: str, db: Session = Depends(get_session)):
    lic = db.exec(select(License).where(License.key == key)).first()
    if not lic: raise HTTPException(status_code=404, detail="License not found")
    lic.status = "revoked"; lic.updated_at = utc_now(); db.add(lic); db.commit()
    return {"ok": True, "status": "revoked"}

# ================== Public Endpoints ==================
@app.post("/activate", tags=["Public"])
def activate(data: ActivateIn, db: Session = Depends(get_session)):
    lic = db.exec(select(License).where(License.key == data.key)).first()
    if not lic or lic.status != "active": raise HTTPException(403, "License invalid")
    expires_at_utc = lic.expires_at.replace(tzinfo=timezone.utc) if lic.expires_at and lic.expires_at.tzinfo is None else lic.expires_at
    if expires_at_utc and expires_at_utc < utc_now(): raise HTTPException(403, "License expired")
    
    actives: List[Activation] = db.exec(select(Activation).where(Activation.license_key == lic.key)).all()
    if not any(a.hwid == data.hwid for a in actives):
        if len(actives) >= lic.max_devices: raise HTTPException(403, f"Seats reached ({lic.max_devices})")
        db.add(Activation(license_key=lic.key, hwid=data.hwid, last_seen_at=utc_now()))
        db.commit()
    
    exp = int(time.time()) + 24 * 3600
    payload = {"k": lic.key, "e": exp, "m": lic.max_devices, "p": lic.plan or "", "kid": KID}
    token = sign_token(PRIV, payload)
    return {"token": token, "exp": exp, "kid": KID, "plan": lic.plan, "max_devices": lic.max_devices}

@app.post("/validate", tags=["Public"])
def validate_token(data: ValidateIn, db: Session = Depends(get_session)):
    try: payload = verify_token(PUB_PEM, data.token)
    except Exception: raise HTTPException(401, "Invalid token")
    lic = db.exec(select(License).where(License.key == payload["k"])).first()
    if not lic or lic.status != "active": raise HTTPException(403, "License invalid")
    act = db.exec(select(Activation).where(Activation.license_key == lic.key, Activation.hwid == data.hwid)).first()
    if not act: raise HTTPException(403, "Device not activated")
    act.last_seen_at = utc_now(); db.add(act); db.commit()
    return {"ok": True, "plan": lic.plan, "max_devices": lic.max_devices, "kid": payload.get("kid")}

@app.post("/deactivate", tags=["Public"])
def deactivate(data: DeactivateIn, db: Session = Depends(get_session)):
    act = db.exec(select(Activation).where(Activation.license_key == data.key, Activation.hwid == data.hwid)).first()
    if not act: raise HTTPException(404, "Activation not found")
    db.delete(act); db.commit()
    return {"ok": True}

@app.post("/license/lookup", tags=["Public"])
def license_lookup(data: LicenseLookupIn, db: Session = Depends(get_session)):
    lic = db.exec(select(License).where(License.key == data.key)).first()
    if not lic: raise HTTPException(404, "Not found")
    if lic.status != "active": raise HTTPException(403, "License invalid")
    return _public_license_dict(lic, db, data.app_ver)

@app.post("/devices/register", tags=["Public"])
def register_device(data: DeviceRegisterIn, db: Session = Depends(get_session)):
    lic = db.exec(select(License).where(License.key == data.key)).first()
    if not lic or lic.status != "active": raise HTTPException(403, "License invalid")
    expires_at_utc = lic.expires_at.replace(tzinfo=timezone.utc) if lic.expires_at and lic.expires_at.tzinfo is None else lic.expires_at
    if expires_at_utc and expires_at_utc < utc_now(): raise HTTPException(403, "License expired")

    dev = db.exec(select(Device).where(Device.license_id == lic.id, Device.hwid == data.hwid)).first()
    if not dev:
        used = scalar_int(db, select(func.count(Device.id)).where(Device.license_id == lic.id))
        if used >= lic.max_devices: raise HTTPException(403, f"Seats reached ({lic.max_devices})")
        dev = Device(license_id=lic.id, hwid=data.hwid)
    
    dev.hostname = data.hostname; dev.platform = data.platform; dev.app_ver = data.app_ver
    dev.last_seen_at = utc_now(); db.add(dev); db.commit(); db.refresh(dev)
    
    used_after = scalar_int(db, select(func.count(Device.id)).where(Device.license_id == lic.id))
    return {"ok": True, "license_key": lic.key, "device_id": dev.id, "used_devices": used_after, "max_devices": lic.max_devices}

# ================== Download Redirect ==================
@app.get("/download", response_class=HTMLResponse, tags=["Download"])
def download_page():
    latest_url = _gh_latest_asset_url(GITHUB_OWNER, GITHUB_REPO, GITHUB_ASSET)
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Tải xuống</title></head><body style="font-family:system-ui; max-width:720px; margin:40px auto; line-height:1.6"><h1>⬇ Tải phần mềm</h1><ul><li><a href="/download/myapp">Tải bản mới nhất (.exe)</a></li><li>Hoặc trỏ thẳng GitHub: <code>{latest_url}</code></li></ul><p>Mẹo: Nếu trình duyệt cảnh báo, hãy chọn “Giữ lại” (Keep) hoặc đóng gói .zip khi phát hành.</p></body></html>"""

@app.get("/download/myapp", tags=["Download"], response_class=RedirectResponse)
def download_latest(request: Request, db: Session = Depends(get_session)):
    url = _gh_latest_asset_url(GITHUB_OWNER, GITHUB_REPO, GITHUB_ASSET)
    try:
        db.add(DownloadLog(path="/download/myapp", ua=request.headers.get("User-Agent"), ip=_client_ip(request), ref=request.headers.get("Referer")))
        db.commit()
    except Exception: db.rollback()
    return RedirectResponse(url, status_code=307)