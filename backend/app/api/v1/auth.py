import uuid

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import PWHASH_MEMLIMIT_DEFAULT, PWHASH_OPSLIMIT_DEFAULT
from app.core.encoding import b64encode
from app.core.limiter import limiter
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    dummy_kdf_salt_for_unknown_email,
    hash_auth_hash,
    verify_auth_hash,
)
from app.db.session import get_db
from app.models.user import User, UserStatus
from app.schemas.auth import AccessTokenResponse, LoginRequest, PreloginRequest, PreloginResponse, RefreshRequest, TokenPair

router = APIRouter(prefix="/auth", tags=["auth"])

# A precomputed argon2 hash of a fixed dummy value, used as the comparison target
# for unknown emails at login - see login() below. Computed once at import time
# (not per-request) so it doesn't itself introduce timing variance.
_DUMMY_AUTH_HASH = hash_auth_hash("infrawarden-dummy-auth-hash-for-timing-safety")


@router.post("/prelogin", response_model=PreloginResponse)
@limiter.limit("20/minute")
async def prelogin(request: Request, body: PreloginRequest, db: AsyncSession = Depends(get_db)) -> PreloginResponse:
    """Returns the KDF params a browser needs to derive auth_hash before it can log
    in - there is no other way for a fresh session to learn a user's kdf_salt/ops/mem.
    Unknown emails get a deterministic fake salt with the platform default ops/mem
    limits instead of a 404, so this endpoint can't be used to enumerate accounts."""
    user = await db.scalar(select(User).where(User.email == body.email))
    if user is None:
        return PreloginResponse(
            kdf_salt=b64encode(dummy_kdf_salt_for_unknown_email(body.email)),
            kdf_ops_limit=PWHASH_OPSLIMIT_DEFAULT,
            kdf_mem_limit=PWHASH_MEMLIMIT_DEFAULT,
        )
    return PreloginResponse(
        kdf_salt=b64encode(user.kdf_salt), kdf_ops_limit=user.kdf_ops_limit, kdf_mem_limit=user.kdf_mem_limit
    )


@router.post("/login", response_model=TokenPair)
@limiter.limit("10/minute")
async def login(request: Request, body: LoginRequest, db: AsyncSession = Depends(get_db)) -> TokenPair:
    user = await db.scalar(select(User).where(User.email == body.email))
    invalid = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    # verify_auth_hash (a real argon2 verify) always runs, even for an unknown
    # email - otherwise this endpoint is a timing oracle for account enumeration,
    # contradicting the whole point of /prelogin's anti-enumeration design:
    # unknown emails would return near-instantly while known emails take the
    # full argon2id verify time, letting an attacker distinguish them by latency.
    stored_hash = user.auth_hash if user is not None else _DUMMY_AUTH_HASH
    hash_valid = verify_auth_hash(body.auth_hash, stored_hash)

    if user is None or user.status != UserStatus.active or not hash_valid:
        raise invalid

    return TokenPair(access_token=create_access_token(user.id), refresh_token=create_refresh_token(user.id))


@router.post("/refresh", response_model=AccessTokenResponse)
async def refresh(body: RefreshRequest, db: AsyncSession = Depends(get_db)) -> AccessTokenResponse:
    invalid = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token")
    try:
        payload = decode_token(body.refresh_token)
    except jwt.PyJWTError:
        raise invalid
    if payload.get("type") != "refresh":
        raise invalid

    user = await db.get(User, uuid.UUID(payload["sub"]))
    if user is None or user.status != UserStatus.active:
        raise invalid

    return AccessTokenResponse(access_token=create_access_token(user.id))


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout() -> None:
    # Access/refresh tokens are stateless JWTs with no server-side session table in
    # the MVP, so there is nothing to revoke here - the client discarding its tokens
    # IS the logout. A future session-revocation table is the natural upgrade path
    # if compromised-token invalidation is ever needed before natural expiry.
    return None
