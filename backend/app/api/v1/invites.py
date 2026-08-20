from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import require_admin
from app.core.encoding import b64decode
from app.core.limiter import limiter
from app.core.security import (
    create_access_token,
    create_refresh_token,
    generate_invite_token,
    hash_auth_hash,
    hash_invite_token,
)
from app.db.session import get_db
from app.models.invite import Invite
from app.models.user import User, UserStatus
from app.schemas.auth import TokenPair
from app.schemas.invite import InviteAccept, InviteCreate, InviteCreated, InvitePublic

router = APIRouter(prefix="/invites", tags=["invites"])

INVITE_TTL_DAYS = 7


@router.post("", response_model=InviteCreated)
async def create_invite(
    body: InviteCreate,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
) -> InviteCreated:
    existing_user = await db.scalar(select(User).where(User.email == body.email))
    if existing_user is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="A user with this email already exists")

    now = datetime.now(timezone.utc)
    existing_live_invite = await db.scalar(
        select(Invite).where(Invite.email == body.email, Invite.accepted_at.is_(None), Invite.expires_at >= now)
    )
    if existing_live_invite is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="An unexpired invite already exists for this email")

    token = generate_invite_token()
    invite = Invite(
        email=body.email,
        invited_by_user_id=admin.id,
        role=body.role,
        token_hash=hash_invite_token(token),
        expires_at=datetime.now(timezone.utc) + timedelta(days=INVITE_TTL_DAYS),
    )
    db.add(invite)
    await db.commit()
    await db.refresh(invite)

    return InviteCreated(
        id=invite.id, email=invite.email, role=invite.role, expires_at=invite.expires_at, token=token
    )


async def _get_valid_invite(token: str, db: AsyncSession) -> Invite:
    invite = await db.scalar(select(Invite).where(Invite.token_hash == hash_invite_token(token)))
    now = datetime.now(timezone.utc)
    if invite is None or invite.accepted_at is not None or invite.expires_at < now:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invite not found or expired")
    return invite


@router.get("/{token}", response_model=InvitePublic)
async def get_invite(token: str, db: AsyncSession = Depends(get_db)) -> InvitePublic:
    invite = await _get_valid_invite(token, db)
    return InvitePublic(email=invite.email, role=invite.role, expires_at=invite.expires_at)


@router.post("/{token}/accept", response_model=TokenPair)
@limiter.limit("10/minute")
async def accept_invite(
    request: Request, token: str, body: InviteAccept, db: AsyncSession = Depends(get_db)
) -> TokenPair:
    invite = await _get_valid_invite(token, db)

    existing_user = await db.scalar(select(User).where(User.email == invite.email))
    if existing_user is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="A user with this email already exists")

    user = User(
        email=invite.email,
        role=invite.role,
        status=UserStatus.active,
        public_key=b64decode(body.public_key),
        wrapped_private_key=b64decode(body.wrapped_private_key),
        wrapped_private_key_nonce=b64decode(body.wrapped_private_key_nonce),
        kdf_salt=b64decode(body.kdf_salt),
        kdf_ops_limit=body.kdf_ops_limit,
        kdf_mem_limit=body.kdf_mem_limit,
        auth_hash=hash_auth_hash(body.auth_hash),
    )
    db.add(user)
    invite.accepted_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(user)

    return TokenPair(access_token=create_access_token(user.id), refresh_token=create_refresh_token(user.id))
