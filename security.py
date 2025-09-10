# security.py
import os, base64, hashlib, textwrap, time, msgpack
from typing import Dict, Any, Tuple
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

# ===== helpers =====
b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")
def b64u_d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def _normalize_pem(s: str) -> str:
    # cho phép dán chuỗi có "\n" literal, chuẩn hoá CRLF -> LF, bỏ khoảng trắng thừa
    return s.replace("\\n", "\n").replace("\r\n", "\n").strip()

def _load_pems(priv_pem: str, pub_pem: str) -> Tuple[Ed25519PrivateKey, bytes]:
    priv = serialization.load_pem_private_key(priv_pem.encode(), password=None)
    pub  = serialization.load_pem_public_key(pub_pem.encode())
    if not isinstance(priv, Ed25519PrivateKey) or not isinstance(pub, Ed25519PublicKey):
        raise RuntimeError("Keys must be Ed25519 PEM.")
    return priv, pub_pem.encode()

# ===== key loading (Cách 1 ưu tiên Secret Files) =====
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def load_keys_from_env() -> Tuple[Ed25519PrivateKey, bytes]:
    # 1) Secret Files trên Render (ưu tiên)
    secret_candidates = [
        ("/etc/secrets/license_private_key.pem", "/etc/secrets/license_public_key.pem"),
        ("/etc/secrets/private.pem",            "/etc/secrets/public.pem"),
    ]
    for priv_path, pub_path in secret_candidates:
        if os.path.exists(priv_path) and os.path.exists(pub_path):
            with open(priv_path, "r", encoding="utf-8") as f: priv_pem = f.read()
            with open(pub_path,  "r", encoding="utf-8") as f: pub_pem  = f.read()
            return _load_pems(_normalize_pem(priv_pem), _normalize_pem(pub_pem))

    # 2) ENV trực tiếp (PEM đa dòng)
    p_priv = os.getenv("PRIVATE_KEY_PEM")
    p_pub  = os.getenv("PUBLIC_KEY_PEM")
    if p_priv and p_pub:
        return _load_pems(_normalize_pem(p_priv), _normalize_pem(p_pub))

    # 3) ENV dạng Base64 (một dòng)
    p_priv_b64 = os.getenv("PRIVATE_KEY_PEM_B64")
    p_pub_b64  = os.getenv("PUBLIC_KEY_PEM_B64")
    if p_priv_b64 and p_pub_b64:
        priv_pem = base64.b64decode(p_priv_b64).decode("utf-8", "strict")
        pub_pem  = base64.b64decode(p_pub_b64 ).decode("utf-8", "strict")
        return _load_pems(_normalize_pem(priv_pem), _normalize_pem(pub_pem))

    # 4) Đường dẫn file do ENV chỉ định (nếu có)
    env_priv_file = os.getenv("PRIVATE_KEY_FILE")
    env_pub_file  = os.getenv("PUBLIC_KEY_FILE")
    if env_priv_file and env_pub_file and os.path.exists(env_priv_file) and os.path.exists(env_pub_file):
        with open(env_priv_file, "r", encoding="utf-8") as f: priv_pem = f.read()
        with open(env_pub_file,  "r", encoding="utf-8") as f: pub_pem  = f.read()
        return _load_pems(_normalize_pem(priv_pem), _normalize_pem(pub_pem))

    # 5) Thư mục Key cục bộ trong repo (fallback local dev)
    local_candidates = [
        (os.path.join(BASE_DIR, "Key",  "license_private_key.pem"),
         os.path.join(BASE_DIR, "Key",  "license_public_key.pem")),
        (os.path.join(BASE_DIR, "keys", "private.pem"),
         os.path.join(BASE_DIR, "keys", "public.pem")),
    ]
    for priv_path, pub_path in local_candidates:
        if os.path.exists(priv_path) and os.path.exists(pub_path):
            with open(priv_path, "r", encoding="utf-8") as f: priv_pem = f.read()
            with open(pub_path,  "r", encoding="utf-8") as f: pub_pem  = f.read()
            return _load_pems(_normalize_pem(priv_pem), _normalize_pem(pub_pem))

    raise RuntimeError(
        "Missing key material. Provide Secret Files at /etc/secrets, "
        "or set PRIVATE_KEY_PEM/PUBLIC_KEY_PEM (or *_B64), "
        "or point to files via PRIVATE_KEY_FILE/PUBLIC_KEY_FILE, "
        "or include Key/license_*.pem locally."
    )

# ===== signing / verifying =====
def kid_from_pub(pub_pem: bytes, length=24) -> str:
    pub = serialization.load_pem_public_key(pub_pem)
    spki = pub.public_bytes(encoding=serialization.Encoding.DER,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo)
    h = hashlib.sha256(spki).digest()
    b32 = base64.b32encode(h).decode().rstrip("=")
    return "-".join(textwrap.wrap(b32[:length], 4))

def sign_token(priv: Ed25519PrivateKey, payload: Dict[str, Any]) -> str:
    body = msgpack.packb(payload, use_bin_type=True)
    sig  = priv.sign(body)
    return f"{b64u(body)}.{b64u(sig)}"

def verify_token(pub_pem: bytes, token: str) -> Dict[str, Any]:
    body_b64, sig_b64 = token.split(".", 1)
    body = b64u_d(body_b64); sig = b64u_d(sig_b64)
    pub = serialization.load_pem_public_key(pub_pem)
    pub.verify(sig, body)
    data = msgpack.unpackb(body, raw=False)
    if "e" in data and int(data["e"]) < int(time.time()):
        raise ValueError("expired")
    return data
