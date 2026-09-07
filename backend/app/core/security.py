"""Security helpers: hashing, JWT, password utilities."""
from __future__ import annotations
import hashlib
import hmac
from datetime import datetime, timedelta, timezone

from app.config import settings


def sha256(data: bytes) -> str:
    """Compute SHA-256 hex digest of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str) -> str:
    """Compute SHA-256 of a file in chunks (memory-safe)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def hmac_sha256(key: str, message: str) -> str:
    """HMAC-SHA256 used for hash-chaining evidence (chain-of-custody)."""
    return hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()


def create_access_token(subject: str, extra: dict | None = None) -> str:
    import jwt

    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes)
    payload = {"sub": subject, "exp": expire}
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict:
    import jwt

    return jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
