import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_client_grant, get_current_user
from app.core.encoding import b64decode, b64encode
from app.db.session import get_db
from app.models.client_timeline_entry import ClientTimelineEntry, TimelineEntrySource
from app.models.resource import Resource
from app.models.user import User
from app.schemas.timeline import TimelineEntryCreate, TimelineEntryOut

router = APIRouter(prefix="/clients/{client_id}/timeline", tags=["timeline"])


def _out(entry: ClientTimelineEntry) -> TimelineEntryOut:
    return TimelineEntryOut(
        id=entry.id,
        client_id=entry.client_id,
        resource_id=entry.resource_id,
        source=entry.source,
        ciphertext=b64encode(entry.ciphertext),
        nonce=b64encode(entry.nonce),
        created_by_user_id=entry.created_by_user_id,
        created_at=entry.created_at,
    )


@router.post("", response_model=TimelineEntryOut)
async def create_timeline_entry(
    client_id: uuid.UUID,
    body: TimelineEntryCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> TimelineEntryOut:
    """MVP only ever writes source='manual' entries here - 'email' is reserved for
    the not-yet-built ingestion pipeline, so this endpoint doesn't accept it."""
    await get_client_grant(client_id, current_user, db)

    if body.resource_id is not None:
        resource = await db.get(Resource, body.resource_id)
        if resource is None or resource.client_id != client_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="resource_id doesn't belong to this client")

    entry = ClientTimelineEntry(
        client_id=client_id,
        resource_id=body.resource_id,
        source=TimelineEntrySource.manual,
        ciphertext=b64decode(body.ciphertext),
        nonce=b64decode(body.nonce),
        created_by_user_id=current_user.id,
    )
    db.add(entry)
    await db.commit()
    await db.refresh(entry)
    return _out(entry)


@router.get("", response_model=list[TimelineEntryOut])
async def list_timeline_entries(
    client_id: uuid.UUID, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)
) -> list[TimelineEntryOut]:
    await get_client_grant(client_id, current_user, db)
    entries = await db.scalars(
        select(ClientTimelineEntry)
        .where(ClientTimelineEntry.client_id == client_id)
        .order_by(ClientTimelineEntry.created_at)
    )
    return [_out(e) for e in entries]
