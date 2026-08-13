from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.api_token import ApiToken


async def check_and_maybe_expire(db: AsyncSession, token: ApiToken) -> bool:
    """Returns True if the token is currently usable. If it's revoked or past its
    TTL, nulls the wrapped data key envelope (if not already null) in the same
    transaction and returns False - this is physical expiry, not just an
    application-level check: after this runs, no correct token_secret can ever
    recover the data key from this row again, even from a raw DB dump."""
    now = datetime.now(timezone.utc)
    if token.revoked_at is not None or token.expires_at < now:
        if token.wrapped_data_key is not None or token.wrapped_data_key_nonce is not None:
            token.wrapped_data_key = None
            token.wrapped_data_key_nonce = None
            await db.commit()
        return False
    return True
