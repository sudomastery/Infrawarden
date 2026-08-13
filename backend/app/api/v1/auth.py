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
    verify_auth_hash,
)
from app.db.session import get_db
from app.models.user import User, UserStatus
from app.schemas.auth import AccessTokenResponse, LoginRequest, PreloginRequest, PreloginResponse, RefreshRequest, TokenPair

router = APIRouter(prefix="/auth", tags=["auth"])


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

    if user is None or user.status != UserStatus.active:
        raise invalid
    if not verify_auth_hash(body.auth_hash, user.auth_hash):
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
