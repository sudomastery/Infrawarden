import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Literal

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from app.core.config import settings

_argon2_hasher = PasswordHasher()

JWT_ALGORITHM = "HS256"


def hash_auth_hash(auth_hash: str) -> str:
    """Server-side rehash of the client-computed login verifier (defense in depth
    against a raw DB dump - auth_hash is already high-entropy KDF output, not a
    guessable secret, so this is a belt-and-suspenders step, not the primary defense)."""
    return _argon2_hasher.hash(auth_hash)


def verify_auth_hash(auth_hash: str, stored_hash: str) -> bool:
    try:
        _argon2_hasher.verify(stored_hash, auth_hash)
        return True
    except VerifyMismatchError:
        return False


def dummy_kdf_salt_for_unknown_email(email: str) -> bytes:
    """Deterministic per-email fake salt for the /auth/prelogin anti-enumeration path:
    an unknown email always gets the same fake salt/params back (not a fresh random
    value each call), so response shape/timing can't be used to tell known accounts
    apart from unknown ones."""
    return hashlib.sha256(f"{settings.jwt_secret}:{email}".encode()).digest()[:16]


def hash_token_secret(token_secret: bytes) -> str:
    """Plain SHA-256, not a slow KDF - correct here because token_secret is 32
    bytes of high-entropy randomness, not a guessable human password."""
    return hashlib.sha256(token_secret).hexdigest()


def generate_invite_token() -> str:
    return secrets.token_urlsafe(32)


def hash_invite_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _create_token(user_id: uuid.UUID, token_type: Literal["access", "refresh"], ttl: timedelta) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "type": token_type,
        "iat": now,
        "exp": now + ttl,
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=JWT_ALGORITHM)


def create_access_token(user_id: uuid.UUID) -> str:
    return _create_token(user_id, "access", timedelta(minutes=settings.jwt_access_token_ttl_minutes))


def create_refresh_token(user_id: uuid.UUID) -> str:
    return _create_token(user_id, "refresh", timedelta(days=settings.jwt_refresh_token_ttl_days))


def decode_token(token: str) -> dict:
    return jwt.decode(token, settings.jwt_secret, algorithms=[JWT_ALGORITHM])
