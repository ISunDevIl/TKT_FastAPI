# app.py
import os
import time
import base64
import datetime as dt
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Depends, Query, Response, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import HTMLResponse, FileResponse
from starlette.middleware.base import BaseHTTPMiddleware

from pydantic import BaseModel, Field as PydField

from sqlalchemy.exc import IntegrityError
from sqlalchemy import UniqueConstraint, CheckConstraint, Column, Text, Index, and_, or_
from sqlalchemy.sql import func
from sqlalchemy.types import DateTime

from sqlmodel import SQLModel, Field, Session, create_engine, select
from sqladmin import Admin, ModelView

from security import load_keys_from_env, kid_from_pub, sign_token, verify_token

# ================== Config ==================
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "change-me")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data.db")

# ================== DB ==================
engine = create_engine(DATABASE_URL, echo=False, pool_pre_ping=True)

def get_session():
    with Session(engine) as s:
        yield s

# ================== Models ==================
class License(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    key: str = Field(index=True, unique=True, nullable=False, max_length=64)
    license: Optional[str] = Field(default=None, sa_column=Column(Text))
    status: str = Field(default="active", max_length=16)
    plan: Optional[str] = Field(default=None, max_length=32)
    max_version: str = Field(default="0.0.1", max_length=50)
    max_devices: int = Field(default=1)
    expires_at: Optional[dt.datetime] = Field(default=None)
    notes: Optional[str] = Field(default=None)
    created_at: dt.datetime = Field(
        sa_column=Column(DateTime(), server_default=func.now(), nullable=False)
    )
    updated_at: dt.datetime = Field(
        sa_column=Column(DateTime(), server_default=func.now(), onupdate=func.now(), nullable=False)
    )

    __table_args__ = (
        CheckConstraint("status in ('active','revoked','deleted')", name="ck_license_status"),
        Index("ix_license_created_at", "created_at"),
        Index("ix_license_updated_at", "updated_at"),
    )

class Device(SQLModel, table=True):
    # Bảng quản lý máy sử dụng license
    id: Optional[int] = Field(default=None, primary_key=True)
    license_id: int = Field(index=True, foreign_key="license.id") # tham chiếu license
    hwid: str = Field(index=True)                                 # mã phần cứng duy nhất
    hostname: Optional[str] = None                                # tên máy (tuỳ chọn)
    platform: Optional[str] = None                                # Windows/Linux/Mac...
    app_ver: Optional[str] = None                                 # version app khi activate
    created_at: dt.datetime = Field(default_factory=dt.datetime.utcnow, index=True)
    last_seen_at: Optional[dt.datetime] = None

    __table_args__ = (
        UniqueConstraint("license_id", "hwid", name="uq_device_license_hwid"),
    )

class Activation(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    license_key: str = Field(index=True, max_length=64)
    hwid: str = Field(max_length=255)
    created_at: dt.datetime = Field(
        sa_column=Column(DateTime(timezone=False), server_default=func.now(), nullable=False)
    )
    last_seen_at: Optional[dt.datetime] = Field(default=None)

    __table_args__ = (
        UniqueConstraint("license_key", "hwid", name="uq_activation_license_hwid"),
        Index("ix_activation_created_at", "created_at"),
    )

# ================== Auth ==================
bearer = HTTPBearer(auto_error=False)
def admin_auth(
    creds: HTTPAuthorizationCredentials = Depends(bearer),
    x_admin_token: str | None = Header(None, alias="X-Admin-Token")
):
    token = creds.credentials if creds else None
    if not token and x_admin_token:
        token = x_admin_token.strip()
    if token != ADMIN_TOKEN:
        raise HTTPException(401, "Unauthorized")
    return True

# ================== Keys ==================
PRIV = None
PUB_PEM = None
KID = None

# ================== Helpers ==================
def now_utc() -> dt.datetime:
    return dt.datetime.utcnow()

# --- short key: TKT-XXXX-XXXX-XXXX ---
def generate_short_key(prefix: str = "TKT", blocks: int = 4, block_size: int = 4) -> str:
    """
    Base32 (A-Z, 2-7), bỏ '='. 10 bytes -> 16 ký tự base32 => 4 block x 4
    Ví dụ: TKT-ABCD-EFGH-JKLM
    """
    raw = base64.b32encode(os.urandom(10)).decode().rstrip("=")
    key_body = "-".join(raw[i:i+block_size] for i in range(0, blocks * block_size, block_size))
    return f"{prefix}-{key_body}"

def _parse_semver(s: Optional[str]) -> tuple[int, int, int]:
    if not s:
        return (0, 0, 0)
    parts = (s or "").strip().split(".")
    out: List[int] = []
    for i in range(3):
        try:
            out.append(int(parts[i]) if i < len(parts) and parts[i] != "" else 0)
        except Exception:
            out.append(0)
    return tuple(out)  # type: ignore[return-value]

def _version_lte(a: Optional[str], b: Optional[str]) -> bool:
    """a <= b theo semver đơn giản x.y.z."""
    return _parse_semver(a) <= _parse_semver(b)

def _public_license_dict(lic: License, db: Session, app_ver: Optional[str] = None) -> dict:
    expired = bool(lic.expires_at and lic.expires_at < now_utc())

    # Đếm thiết bị từ bảng device (đúng với seats)
    used_devices_count = db.exec(
        select(func.count(Device.id)).where(Device.license_id == lic.id)
    ).one()
    # một số driver trả tuple
    if isinstance(used_devices_count, tuple):
        used_devices_count = used_devices_count[0]
    used_devices_count = int(used_devices_count)

    resp = {
        "key": lic.key,
        "status": lic.status,
        "plan": lic.plan,
        "max_devices": lic.max_devices,
        "used_devices": used_devices_count,  # <-- đếm theo device
        "max_version": lic.max_version,
        "expires_at": lic.expires_at.isoformat() + "Z" if lic.expires_at else None,
        "license": lic.license,
        "kid": KID,
        "now": int(time.time()),
        "expired": expired,
    }
    if app_ver is not None and lic.max_version:
        resp["app_ver"] = app_ver
        resp["app_allowed"] = _version_lte(app_ver, lic.max_version)
    return resp

# ================== App ==================
BOOT_TS = time.time()
app = FastAPI(title="License Server (Render)", version="1.0.0")

# ---- SQLAdmin & middleware bảo vệ /admin ----
class AdminAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if request.url.path.startswith("/admin"):
            expect = ADMIN_TOKEN
            ok = False
            auth = request.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                ok = (auth.split(" ", 1)[1].strip() == expect)
            if not ok:
                xadm = request.headers.get("X-Admin-Token")
                ok = bool(xadm and xadm.strip() == expect)
            if not ok:
                return Response("Unauthorized", status_code=401)
        return await call_next(request)

app.add_middleware(AdminAuthMiddleware)
admin = Admin(app, engine)

class LicenseAdmin(ModelView, model=License):
    name = "License"; name_plural = "Licenses"
    column_list = [
        License.id, License.key, License.status, License.plan,
        License.max_devices, License.expires_at, License.created_at, License.updated_at
    ]
    column_searchable_list = [License.key, License.plan, License.status]
    column_sortable_list = [License.id, License.created_at, License.expires_at, License.updated_at]

class ActivationAdmin(ModelView, model=Activation):
    name = "Activation"; name_plural = "Activations"
    column_list = [
        Activation.id, Activation.license_key, Activation.hwid,
        Activation.created_at, Activation.last_seen_at
    ]
    column_searchable_list = [Activation.license_key, Activation.hwid]
    column_sortable_list = [Activation.id, Activation.created_at, Activation.last_seen_at]

admin.add_view(LicenseAdmin)
admin.add_view(ActivationAdmin)
# -------------------------------------------

# ================== Lifecycle & Static ==================
@app.on_event("startup")
def startup():
    global PRIV, PUB_PEM, KID
    SQLModel.metadata.create_all(engine)
    PRIV, PUB_PEM = load_keys_from_env()
    KID = kid_from_pub(PUB_PEM)

@app.get("/health")
def health():
    return {"ok": True, "kid": KID}

@app.get("/healthz")
def healthz():
    return {"status": "ok", "uptime": round(time.time() - BOOT_TS, 2)}

@app.get("/ready")
def ready():
    return {"ready": True, "kid": KID}

@app.get("/", response_class=HTMLResponse)
def index():
    uptime = round(time.time() - BOOT_TS, 2)
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>TKT FastAPI</title></head>
<body style="font-family:system-ui; max-width:720px; margin:40px auto; line-height:1.6">
  <h1>✅ TKT FastAPI is live</h1>
  <h4>When you die, you can't see sunsets. </h4>
  <p>Uptime: <b>{uptime}s</b></p>
  <p>Active KID: <code>{KID}</code></p>
  <ul>
    <li><a href="/healthz">/healthz</a></li>
    <li><a href="/ready">/ready</a></li>
    <li><a href="/docs">/docs</a></li>
    <li><a href="/admin">/admin</a> (thêm header Authorization: Bearer ...)</li>
  </ul>
</body></html>"""

@app.head("/")
def index_head():
    return Response(status_code=200)

@app.get("/favicon.ico")
def favicon():
    path = os.path.join(os.path.dirname(__file__), "static", "favicon.ico")
    if os.path.exists(path):
        return FileResponse(path, media_type="image/x-icon")
    return Response(status_code=204)

# ================== Schemas ==================
class LicenseCreate(BaseModel):
    key: Optional[str] = None
    license: Optional[str] = None
    plan: Optional[str] = None
    max_devices: int = PydField(default=1, ge=1)
    max_version: Optional[str] = None
    expires_days: Optional[int] = PydField(default=365, ge=1)
    notes: Optional[str] = None

class LicenseUpdate(BaseModel):
    status: Optional[str] = None
    plan: Optional[str] = None
    max_devices: Optional[int] = PydField(default=None, ge=1)
    expires_days: Optional[int] = PydField(default=None, ge=1)
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

class LicenseListResponse(BaseModel):
    items: List[LicenseItem]
    total: int
    page: int
    page_size: int
    pages: int

class DeviceRegisterIn(BaseModel):
    key: str
    hwid: str
    hostname: Optional[str] = None
    platform: Optional[str] = None
    app_ver: Optional[str] = None

# ================== Admin CRUD ==================
ALLOWED_PLANS = {"Free", "Plus", "Pro"}

@app.post("/licenses", dependencies=[Depends(admin_auth)])
def create_license(data: LicenseCreate, db: Session = Depends(get_session)):
    if data.plan and data.plan not in ALLOWED_PLANS:
        raise HTTPException(status_code=422, detail=f"plan phải thuộc {sorted(ALLOWED_PLANS)}")

    # sinh hoặc dùng key truyền lên
    key = data.key or generate_short_key()
    tries = 0
    while db.exec(select(License).where(License.key == key)).first():
        tries += 1
        if tries > 5:
            raise HTTPException(500, "Cannot generate unique key")
        key = generate_short_key()

    lic = License(key=key)

    if data.license is not None:
        lic.license = data.license
    if data.plan is not None:
        lic.plan = data.plan
    if data.max_devices is not None:
        lic.max_devices = data.max_devices
    if data.max_version is not None:
        lic.max_version = data.max_version
    if data.notes is not None:
        lic.notes = data.notes
    if data.expires_days:
        lic.expires_at = now_utc() + dt.timedelta(days=data.expires_days)

    try:
        db.add(lic)
        db.commit()
        db.refresh(lic)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Key đã tồn tại hoặc dữ liệu không hợp lệ")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Lỗi lưu DB: {e}")

    return {
        "id": lic.id,
        "key": lic.key,
        "license": lic.license,
        "plan": lic.plan,
        "max_devices": lic.max_devices,
        "max_version": lic.max_version,
        "expires_at": lic.expires_at.isoformat() + "Z" if lic.expires_at else None,
        "notes": lic.notes,
        "created_at": lic.created_at.isoformat() + "Z" if getattr(lic, "created_at", None) else None,
    }

@app.get("/licenses", response_model=LicenseListResponse, dependencies=[Depends(admin_auth)])
def list_licenses(
    db: Session = Depends(get_session),
    # Tìm kiếm & lọc
    q: Optional[str] = Query(None, description="Tìm theo key/plan/status (substring)"),
    status: Optional[str] = Query(None, description="Lọc theo trạng thái: active/revoked/deleted"),
    plan: Optional[str] = Query(None, description="Lọc theo gói: Free/Plus/Pro"),
    created_from: Optional[dt.datetime] = Query(None),
    created_to: Optional[dt.datetime] = Query(None),
    expires_from: Optional[dt.datetime] = Query(None),
    expires_to: Optional[dt.datetime] = Query(None),
    # Phân trang
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
    # Sắp xếp
    sort_by: str = Query("created_at", pattern="^(created_at|updated_at|expires_at|key)$"),
    sort_dir: str = Query("desc", pattern="^(asc|desc)$"),
):
    def _iso(x: Optional[dt.datetime]) -> Optional[str]:
        if not x:
            return None
        # Chuẩn hóa ISO dạng UTC naive + 'Z' (đồng bộ với các field khác của bạn)
        return x.isoformat() + "Z"

    # ----- Build bộ lọc -----
    filters = []
    if q:
        like = f"%{q}%"
        filters.append(or_(License.key.ilike(like), License.plan.ilike(like), License.status.ilike(like)))
    if status:
        filters.append(License.status == status)
    if plan:
        filters.append(License.plan == plan)
    if created_from:
        filters.append(License.created_at >= created_from)
    if created_to:
        filters.append(License.created_at <= created_to)
    if expires_from:
        filters.append(License.expires_at != None)  # tránh so sánh NULL
        filters.append(License.expires_at >= expires_from)
    if expires_to:
        filters.append(License.expires_at != None)
        filters.append(License.expires_at <= expires_to)

    where_clause = and_(*filters) if filters else None

    # ----- Tổng số bản ghi -----
    count_stmt = select(func.count()).select_from(License)
    if where_clause is not None:
        count_stmt = count_stmt.where(where_clause)
    total = db.exec(count_stmt).one()
    if isinstance(total, tuple):  # phòng khi driver trả về tuple
        total = total[0]
    total = int(total)

    # ----- Sắp xếp -----
    sort_map = {
        "created_at": License.created_at,
        "updated_at": License.updated_at,
        "expires_at": License.expires_at,
        "key": License.key,
    }
    order_col = sort_map.get(sort_by, License.created_at)
    order_by = order_col.desc() if sort_dir == "desc" else order_col.asc()

    # ----- Lấy dữ liệu theo trang -----
    offset = (page - 1) * page_size
    stmt = select(License).order_by(order_by).offset(offset).limit(page_size)
    if where_clause is not None:
        stmt = stmt.where(where_clause)

    licenses: List[License] = db.exec(stmt).all()

    # ----- Tính used_devices cho tất cả key trong 1 query -----
    if licenses:
        lic_ids = [lic.id for lic in licenses]
        cnt_stmt = (
            select(Device.license_id, func.count(Device.id))
            .where(Device.license_id.in_(lic_ids))
            .group_by(Device.license_id)
        )
        counts = dict(db.exec(cnt_stmt).all())  # {license_id: count}
    else:
        counts = {}

    # ----- Map ra response items -----
    items: List[LicenseItem] = []
    for lic in licenses:
        items.append(
            LicenseItem(
                id=lic.id,
                key=lic.key,
                status=lic.status,
                plan=lic.plan,
                max_devices=int(counts.get(lic.id, 0)),
                used_devices=int(counts.get(lic.key, 0)),
                max_version=lic.max_version,
                expires_at=_iso(lic.expires_at),
                created_at=_iso(getattr(lic, "created_at", None)),
                updated_at=_iso(getattr(lic, "updated_at", None)),
            )
        )

    pages = (total + page_size - 1) // page_size
    return {"items": items, "total": total, "page": page, "page_size": page_size, "pages": pages}


@app.get("/licenses/{key}", dependencies=[Depends(admin_auth)])
def get_license_detail(key: str, db: Session = Depends(get_session)):
    lic = db.exec(select(License).where(License.key == key)).first()
    if not lic:
        raise HTTPException(404, "Not found")
    acts = db.exec(
        select(Activation).where(Activation.license_key == key).order_by(Activation.created_at.desc())
    ).all()
    return {"license": lic, "activations": acts}

@app.patch("/licenses/{key}", dependencies=[Depends(admin_auth)])
def update_license(key: str, data: LicenseUpdate, db: Session = Depends(get_session)):
    lic = db.exec(select(License).where(License.key == key)).first()
    if not lic:
        raise HTTPException(404, "Not found")

    for k, v in data.model_dump(exclude_unset=True).items():
        if k == "expires_days" and v is not None:
            lic.expires_at = now_utc() + dt.timedelta(days=v)
        elif k != "expires_days":
            setattr(lic, k, v)

    lic.updated_at = now_utc()
    db.add(lic); db.commit(); db.refresh(lic)
    return {"ok": True}

@app.delete("/licenses/{key}", dependencies=[Depends(admin_auth)])
def delete_license(key: str, db: Session = Depends(get_session)):
    lic = db.exec(select(License).where(License.key == key)).first()
    if not lic:
        raise HTTPException(404, "Not found")
    lic.status = "deleted"
    db.add(lic); db.commit()
    return {"ok": True}

@app.post("/revoke/{key}", dependencies=[Depends(admin_auth)])
def revoke(key: str, db: Session = Depends(get_session)):
    lic = db.exec(select(License).where(License.key == key)).first()
    if not lic:
        raise HTTPException(404, "Not found")
    lic.status = "revoked"
    db.add(lic); db.commit()
    return {"ok": True}

@app.get("/activations", dependencies=[Depends(admin_auth)])
def list_activations(key: Optional[str] = Query(None), db: Session = Depends(get_session)):
    stmt = select(Activation)
    if key:
        stmt = stmt.where(Activation.license_key == key)
    return db.exec(stmt.order_by(Activation.created_at.desc())).all()

# ================== Public: Activate / Validate / Deactivate ==================
@app.post("/activate")
def activate(data: ActivateIn, db: Session = Depends(get_session)):
    lic = db.exec(select(License).where(License.key == data.key)).first()
    if not lic or lic.status != "active":
        raise HTTPException(403, "License invalid")
    if lic.expires_at and lic.expires_at < now_utc():
        raise HTTPException(403, "License expired")

    actives: List[Activation] = db.exec(select(Activation).where(Activation.license_key == lic.key)).all()
    if not any(a.hwid == data.hwid for a in actives):
        if len(actives) >= lic.max_devices:
            raise HTTPException(403, f"Seats reached ({lic.max_devices})")
        db.add(Activation(license_key=lic.key, hwid=data.hwid))
        db.commit()

    # Token TTL 24h để revoke nhanh
    exp = int(time.time()) + 24 * 3600
    payload = {"k": lic.key, "e": exp, "m": lic.max_devices, "p": lic.plan or "", "kid": KID}
    token = sign_token(PRIV, payload)
    return {"token": token, "exp": exp, "kid": KID, "plan": lic.plan, "max_devices": lic.max_devices}

@app.post("/validate")
def validate_token(data: ValidateIn, db: Session = Depends(get_session)):
    try:
        payload = verify_token(PUB_PEM, data.token)
    except Exception:
        raise HTTPException(401, "Invalid token")

    lic = db.exec(select(License).where(License.key == payload["k"])).first()
    if not lic or lic.status != "active":
        raise HTTPException(403, "License invalid")

    act = db.exec(
        select(Activation).where(Activation.license_key == lic.key, Activation.hwid == data.hwid)
    ).first()
    if not act:
        raise HTTPException(403, "Device not activated")

    act.last_seen_at = now_utc()
    db.add(act); db.commit()

    return {"ok": True, "plan": lic.plan, "max_devices": lic.max_devices, "kid": payload.get("kid")}

@app.post("/deactivate")
def deactivate(data: DeactivateIn, db: Session = Depends(get_session)):
    act = db.exec(
        select(Activation).where(Activation.license_key == data.key, Activation.hwid == data.hwid)
    ).first()
    if not act:
        raise HTTPException(404, "Activation not found")
    db.delete(act); db.commit()
    return {"ok": True}

@app.post("/license/lookup")
def license_lookup(data: LicenseLookupIn, db: Session = Depends(get_session)):
    lic = db.exec(select(License).where(License.key == data.key)).first()
    if not lic:
        raise HTTPException(404, "Not found")
    if lic.status != "active":
        raise HTTPException(403, "License invalid")
    return _public_license_dict(lic, db, data.app_ver)

@app.get("/licenses/{key}/public")
def get_license_public(key: str, app_ver: Optional[str] = None, db: Session = Depends(get_session)):
    lic = db.exec(select(License).where(License.key == key)).first()
    if not lic:
        raise HTTPException(404, "Not found")
    if lic.status != "active":
        raise HTTPException(403, "License invalid")
    return _public_license_dict(lic, db, app_ver)

@app.post("/devices/register")
def register_device(data: DeviceRegisterIn, db: Session = Depends(get_session)):
    # Tìm license
    lic = db.exec(select(License).where(License.key == data.key)).first()
    if not lic or lic.status != "active":
        raise HTTPException(403, "License invalid")
    if lic.expires_at and lic.expires_at < dt.datetime.utcnow():
        raise HTTPException(403, "License expired")

    # Upsert theo (license_id, hwid)
    dev = db.exec(
        select(Device).where(Device.license_id == lic.id, Device.hwid == data.hwid)
    ).first()

    if not dev:
        # kiểm tra seats
        used = db.exec(
            select(func.count(Device.id)).where(Device.license_id == lic.id)
        ).one()[0]
        if used >= lic.max_devices:
            raise HTTPException(403, f"Seats reached ({lic.max_devices})")

        dev = Device(
            license_id=lic.id,
            hwid=data.hwid,
            hostname=data.hostname,
            platform=data.platform,
            app_ver=data.app_ver,
        )
        db.add(dev)
        db.commit()
        db.refresh(dev)
    else:
        # update thông tin + last_seen
        changed = False
        if data.hostname and data.hostname != dev.hostname:
            dev.hostname = data.hostname; changed = True
        if data.platform and data.platform != dev.platform:
            dev.platform = data.platform; changed = True
        if data.app_ver and data.app_ver != dev.app_ver:
            dev.app_ver = data.app_ver; changed = True
        dev.last_seen_at = dt.datetime.utcnow(); changed = True
        if changed:
            db.add(dev); db.commit(); db.refresh(dev)

    used_after = db.exec(
        select(func.count(Device.id)).where(Device.license_id == lic.id)
    ).one()[0]

    return {
        "ok": True,
        "license_key": lic.key,
        "device_id": dev.id,
        "used_devices": used_after,
        "max_devices": lic.max_devices,
    }
