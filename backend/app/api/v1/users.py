from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user
from app.core.encoding import b64encode
from app.db.session import get_db
from app.models.user import User
from app.schemas.user import UserMe, UserPublic

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=UserMe)
async def get_me(current_user: User = Depends(get_current_user)) -> UserMe:
    return UserMe(
        id=current_user.id,
        email=current_user.email,
        role=current_user.role,
        status=current_user.status,
        public_key=b64encode(current_user.public_key),
        wrapped_private_key=b64encode(current_user.wrapped_private_key),
        wrapped_private_key_nonce=b64encode(current_user.wrapped_private_key_nonce),
        kdf_salt=b64encode(current_user.kdf_salt),
        kdf_ops_limit=current_user.kdf_ops_limit,
        kdf_mem_limit=current_user.kdf_mem_limit,
    )


@router.get("", response_model=list[UserPublic])
async def list_users(
    db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)
) -> list[UserPublic]:
    users = await db.scalars(select(User))
    return [UserPublic(id=u.id, email=u.email, role=u.role, public_key=b64encode(u.public_key)) for u in users]
