import os, time, datetime, base64
from typing import Optional, List
from fastapi import FastAPI, HTTPException, Depends, Query, Response, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import HTMLResponse, FileResponse
from sqlmodel import SQLModel, Field, Session, create_engine, select
from sqladmin import Admin, ModelView
from starlette.middleware.base import BaseHTTPMiddleware
from sqlalchemy.exc import IntegrityError
import datetime as dt
from pydantic import BaseModel, Field as PydField

from security import load_keys_from_env, kid_from_pub, sign_token, verify_token

# ================== Config ==================
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "change-me")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data.db")  # Render sẽ override bằng Postgres

# --- helper sinh key ngắn gọn, dạng TKT-XXXX-XXXX-XXXX ---
def generate_short_key(prefix: str = "TKT", blocks: int = 4, block_size: int = 4) -> str:
    """
    Sinh key ngắn gọn dùng Base32 chuẩn (A-Z, 2-7), bỏ dấu '='.
    10 bytes -> 16 ký tự base32 => đủ 4 block x 4
    Ví dụ: TKT-ABCD-EFGH-JKLM
    """
    raw = base64.b32encode(os.urandom(10)).decode().rstrip("=")  # 16 ký tự
    key_body = "-".join(raw[i:i+block_size] for i in range(0, blocks * block_size, block_size))
    return f"{prefix}-{key_body}"

# ================== DB ==================
engine = create_engine(DATABASE_URL, echo=False, pool_pre_ping=True)
def get_session():
    with Session(engine) as s:
        yield s

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

# ====== Schemas ======
class LicenseCreate(BaseModel):
    key: Optional[str] = None
    license: Optional[str] = None              # <-- thêm
    plan: Optional[str] = None
    max_devices: int = PydField(default=1, ge=1)
    max_version: Optional[str] = None          # <-- thêm (dạng "1.0.1")
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

# ====== Admin CRUD ======
ALLOWED_PLANS = {"Free", "Basic", "Pro", "Enterprise"}  # đồng bộ với client
@app.post("/licenses", dependencies=[Depends(admin_auth)])
def create_license(data: LicenseCreate, db: Session = Depends(get_session)):
    # ----- Validate cơ bản -----
    if data.plan and data.plan not in ALLOWED_PLANS:
        raise HTTPException(status_code=422, detail=f"plan phải thuộc {sorted(ALLOWED_PLANS)}")

    # ----- Tạo hoặc dùng key gửi lên -----
    key = data.key or generate_short_key()
    tries = 0
    while db.exec(select(License).where(License.key == key)).first():
        tries += 1
        if tries > 5:
            raise HTTPException(500, "Cannot generate unique key")
        key = generate_short_key()

    # ----- Khởi tạo bản ghi: chỉ gán field nếu có dữ liệu -----
    lic = License(key=key)

    if data.license is not None:
        lic.license = data.license

    if data.plan is not None:
        lic.plan = data.plan

    if data.max_devices is not None:
        lic.max_devices = data.max_devices

    if data.max_version is not None:
        lic.max_version = data.max_version   # nếu không gửi, giữ default "0.0.1" của model

    if data.notes is not None:
        lic.notes = data.notes

    if data.expires_days:
        lic.expires_at = dt.datetime.utcnow() + dt.timedelta(days=data.expires_days)

    try:
        db.add(lic)
        db.commit()
        db.refresh(lic)
    except IntegrityError as e:
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

@app.get("/licenses", dependencies=[Depends(admin_auth)])
def list_licenses(q: Optional[str] = None, db: Session = Depends(get_session)):
    stmt = select(License)
    if q:
        stmt = stmt.where(License.key.contains(q))
    return db.exec(stmt.order_by(License.created_at.desc())).all()

# NEW: xem chi tiết 1 license + các activation
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
            lic.expires_at = datetime.datetime.utcnow() + datetime.timedelta(days=v)
        elif k != "expires_days":
            setattr(lic, k, v)
    lic.updated_at = datetime.datetime.utcnow()
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

# NEW: liệt kê activations (có thể lọc theo key)
@app.get("/activations", dependencies=[Depends(admin_auth)])
def list_activations(key: Optional[str] = Query(None), db: Session = Depends(get_session)):
    stmt = select(Activation)
    if key:
        stmt = stmt.where(Activation.license_key == key)
    return db.exec(stmt.order_by(Activation.created_at.desc())).all()

# ====== Activate / Validate / Deactivate ======
@app.post("/activate")
def activate(data: ActivateIn, db: Session = Depends(get_session)):
    lic = db.exec(select(License).where(License.key == data.key)).first()
    if not lic or lic.status != "active":
        raise HTTPException(403, "License invalid")
    if lic.expires_at and lic.expires_at < datetime.datetime.utcnow():
        raise HTTPException(403, "License expired")

    actives: List[Activation] = db.exec(select(Activation).where(Activation.license_key == lic.key)).all()
    if not any(a.hwid == data.hwid for a in actives):
        if len(actives) >= lic.max_devices:
            raise HTTPException(403, f"Seats reached ({lic.max_devices})")
        db.add(Activation(license_key=lic.key, hwid=data.hwid))
        db.commit()

    # Token TTL 24h để revoke nhanh
    exp = int(time.time()) + 24*3600
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
    act.last_seen_at = datetime.datetime.utcnow()
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
