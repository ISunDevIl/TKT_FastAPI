# app.py
import os, time, datetime
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from sqlmodel import SQLModel, Session, create_engine, select

from models import License, Activation  # <-- models tách riêng
from security import load_keys_from_env, kid_from_pub, sign_token, verify_token

# ================== Config ==================
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "change-me")

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data.db")
# Chuẩn hoá URL cho SQLAlchemy nếu là dạng postgres://
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# ================== DB ==================
engine = create_engine(DATABASE_URL, echo=False, pool_pre_ping=True)

def get_session():
    with Session(engine) as s:
        yield s

# ================== App & Keys ==================
app = FastAPI(title="License Server (Render)", version="1.0.0")

# Khóa sẽ được nạp trong startup (không nạp khi import để tránh lỗi alembic)
PRIV = None
PUB_PEM = None
KID = None

@app.on_event("startup")
def startup():
    """Tạo bảng & nạp khóa ký từ ENV / file khi app chạy thật sự."""
    global PRIV, PUB_PEM, KID
    SQLModel.metadata.create_all(engine)
    # Nạp khoá: hỗ trợ PRIVATE_KEY_PEM/PUBLIC_KEY_PEM, *_B64, hoặc *_FILE
    PRIV, PUB_PEM = load_keys_from_env()
    KID = kid_from_pub(PUB_PEM)

# ================== Auth ==================
bearer = HTTPBearer(auto_error=False)

def admin_auth(creds: HTTPAuthorizationCredentials = Depends(bearer)):
    if not creds or creds.credentials != ADMIN_TOKEN:
        raise HTTPException(401, "Unauthorized")
    return True

# ================== Schemas ==================
class LicenseCreate(BaseModel):
    key: str
    plan: Optional[str] = None
    max_devices: int = 1
    expires_days: Optional[int] = 365

class LicenseUpdate(BaseModel):
    status: Optional[str] = None
    plan: Optional[str] = None
    max_devices: Optional[int] = None
    expires_days: Optional[int] = None
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

# ================== Health ==================
@app.get("/health")
def health():
    return {"ok": True, "kid": KID is not None and KID or None}

# ================== Admin CRUD ==================
@app.post("/licenses", dependencies=[Depends(admin_auth)])
def create_license(data: LicenseCreate, db: Session = Depends(get_session)):
    if db.exec(select(License).where(License.key == data.key)).first():
        raise HTTPException(400, "Key exists")
    lic = License(key=data.key, plan=data.plan, max_devices=data.max_devices)
    if data.expires_days:
        lic.expires_at = datetime.datetime.utcnow() + datetime.timedelta(days=data.expires_days)
    db.add(lic)
    db.commit()
    db.refresh(lic)
    return {"id": lic.id, "key": lic.key}

@app.get("/licenses", dependencies=[Depends(admin_auth)])
def list_licenses(q: Optional[str] = None, db: Session = Depends(get_session)):
    stmt = select(License)
    if q:
        stmt = stmt.where(License.key.contains(q))
    return db.exec(stmt.order_by(License.created_at.desc())).all()

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
    db.add(lic)
    db.commit()
    db.refresh(lic)
    return {"ok": True}

@app.delete("/licenses/{key}", dependencies=[Depends(admin_auth)])
def delete_license(key: str, db: Session = Depends(get_session)):
    lic = db.exec(select(License).where(License.key == key)).first()
    if not lic:
        raise HTTPException(404, "Not found")
    lic.status = "deleted"
    db.add(lic)
    db.commit()
    # (tuỳ chọn) xóa activations liên quan: db.exec(delete(Activation).where(...))
    return {"ok": True}

@app.post("/revoke/{key}", dependencies=[Depends(admin_auth)])
def revoke(key: str, db: Session = Depends(get_session)):
    lic = db.exec(select(License).where(License.key == key)).first()
    if not lic:
        raise HTTPException(404, "Not found")
    lic.status = "revoked"
    db.add(lic)
    db.commit()
    return {"ok": True}

# ================== Activate / Validate / Deactivate ==================
@app.post("/activate")
def activate(data: ActivateIn, db: Session = Depends(get_session)):
    # Đảm bảo khóa đã nạp
    if PRIV is None:
        raise HTTPException(500, "Signing key not loaded")

    lic = db.exec(select(License).where(License.key == data.key)).first()
    if not lic or lic.status != "active":
        raise HTTPException(403, "License invalid")
    if lic.expires_at and lic.expires_at < datetime.datetime.utcnow():
        raise HTTPException(403, "License expired")

    actives: List[Activation] = db.exec(
        select(Activation).where(Activation.license_key == lic.key)
    ).all()

    if not any(a.hwid == data.hwid for a in actives):
        if len(actives) >= lic.max_devices:
            raise HTTPException(403, f"Seats reached ({lic.max_devices})")
        db.add(Activation(license_key=lic.key, hwid=data.hwid))
        db.commit()

    # Token TTL ngắn để revoke nhanh (24h)
    exp = int(time.time()) + 24 * 3600
    payload = {"k": lic.key, "e": exp, "m": lic.max_devices, "p": lic.plan or "", "kid": KID}
    token = sign_token(PRIV, payload)
    return {"token": token, "exp": exp, "kid": KID, "plan": lic.plan, "max_devices": lic.max_devices}

@app.post("/validate")
def validate_token(data: ValidateIn, db: Session = Depends(get_session)):
    if PUB_PEM is None:
        raise HTTPException(500, "Public key not loaded")
    try:
        payload = verify_token(PUB_PEM, data.token)
    except Exception:
        raise HTTPException(401, "Invalid token")

    lic = db.exec(select(License).where(License.key == payload["k"])).first()
    if not lic or lic.status != "active":
        raise HTTPException(403, "License invalid")

    act = db.exec(
        select(Activation).where(
            Activation.license_key == lic.key,
            Activation.hwid == data.hwid
        )
    ).first()
    if not act:
        raise HTTPException(403, "Device not activated")

    act.last_seen_at = datetime.datetime.utcnow()
    db.add(act)
    db.commit()

    return {"ok": True, "plan": lic.plan, "max_devices": lic.max_devices, "kid": payload.get("kid")}

@app.post("/deactivate")
def deactivate(data: DeactivateIn, db: Session = Depends(get_session)):
    act = db.exec(
        select(Activation).where(
            Activation.license_key == data.key,
            Activation.hwid == data.hwid
        )
    ).first()
    if not act:
        raise HTTPException(404, "Activation not found")
    db.delete(act)
    db.commit()
    return {"ok": True}
