# security.py
import os, base64, hashlib, textwrap, time, msgpack
from typing import Dict, Any, Tuple
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")
def b64u_d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def _normalize_pem(s: str) -> str:
    # cho phép dán chuỗi có "\n" thành newline thật
    return s.replace("\\n", "\n").strip()

def _load_pems(priv_pem: str, pub_pem: str):
    priv = serialization.load_pem_private_key(priv_pem.encode(), password=None)
    pub  = serialization.load_pem_public_key(pub_pem.encode())
    if not isinstance(priv, Ed25519PrivateKey) or not isinstance(pub, Ed25519PublicKey):
        raise RuntimeError("Keys must be Ed25519 PEM.")
    return priv, pub_pem.encode()

def load_keys_from_env() -> Tuple[Ed25519PrivateKey, bytes]:
    # 1) PEM trực tiếp (đa dòng)
    p_priv = os.getenv("PRIVATE_KEY_PEM")
    p_pub  = os.getenv("PUBLIC_KEY_PEM")
    if p_priv and p_pub:
        return _load_pems(_normalize_pem(p_priv), _normalize_pem(p_pub))

    # 2) BASE64
    p_priv_b64 = os.getenv("PRIVATE_KEY_PEM_B64")
    p_pub_b64  = os.getenv("PUBLIC_KEY_PEM_B64")
    if p_priv_b64 and p_pub_b64:
        return _load_pems(
            base64.b64decode(p_priv_b64).decode().strip(),
            base64.b64decode(p_pub_b64).decode().strip()
        )

    # 3) FILE path
    priv_file = os.getenv("PRIVATE_KEY_FILE", "keys/private.pem")
    pub_file  = os.getenv("PUBLIC_KEY_FILE",  "keys/public.pem")
    if os.path.exists(priv_file) and os.path.exists(pub_file):
        with open(priv_file, "r") as f: priv_pem = f.read()
        with open(pub_file, "r") as f: pub_pem  = f.read()
        return _load_pems(priv_pem, pub_pem)

    raise RuntimeError("Missing key material. Set PRIVATE_KEY_PEM/PUBLIC_KEY_PEM "
                       "or *_B64, or PRIVATE_KEY_FILE/PUBLIC_KEY_FILE.")

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
