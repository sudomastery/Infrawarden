import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_client_grant, get_current_user
from app.core.encoding import b64decode, b64encode
from app.db.session import get_db
from app.models.client_access_grant import ClientAccessGrant
from app.models.resource import Resource, ResourceStatus
from app.models.resource_note import ResourceNote
from app.models.resource_user_state import ResourceUserState
from app.models.resource_version import ResourceVersion
from app.models.user import User, UserRole
from app.schemas.resource import (
    ResourceCreate,
    ResourceNoteCreate,
    ResourceNoteOut,
    ResourceOut,
    ResourceStateOut,
    ResourceVersionCreate,
    ResourceVersionOut,
)

router = APIRouter(tags=["resources"])


def _version_out(v: ResourceVersion) -> ResourceVersionOut:
    return ResourceVersionOut(
        id=v.id,
        changed_by_user_id=v.changed_by_user_id,
        ciphertext=b64encode(v.ciphertext),
        nonce=b64encode(v.nonce),
        created_at=v.created_at,
    )


async def _get_active_resource(resource_id: uuid.UUID, user: User, db: AsyncSession) -> Resource:
    resource = await db.get(Resource, resource_id)
    if resource is None or resource.status != ResourceStatus.active:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found")
    await get_client_grant(resource.client_id, user, db)
    return resource


async def _resource_out(resource: Resource, user: User, db: AsyncSession) -> ResourceOut:
    state = await db.get(ResourceUserState, (resource.id, user.id))
    current_version_id = state.current_version_id if state else resource.latest_version_id
    current_version = await db.get(ResourceVersion, current_version_id)
    return ResourceOut(
        id=resource.id,
        client_id=resource.client_id,
        resource_type=resource.resource_type,
        created_by_user_id=resource.created_by_user_id,
        status=resource.status,
        latest_version_id=resource.latest_version_id,
        current_version=_version_out(current_version),
        has_pending_change=current_version_id != resource.latest_version_id,
        hidden=bool(state and state.hidden_at is not None),
        created_at=resource.created_at,
        updated_at=resource.updated_at,
    )


@router.post("/clients/{client_id}/resources", response_model=ResourceOut)
async def create_resource(
    client_id: uuid.UUID,
    body: ResourceCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ResourceOut:
    await get_client_grant(client_id, current_user, db)

    resource = Resource(
        client_id=client_id, resource_type=body.resource_type, created_by_user_id=current_user.id
    )
    db.add(resource)
    await db.flush()

    version = ResourceVersion(
        resource_id=resource.id,
        ciphertext=b64decode(body.ciphertext),
        nonce=b64decode(body.nonce),
        changed_by_user_id=current_user.id,
    )
    db.add(version)
    await db.flush()

    resource.latest_version_id = version.id

    # New resource: every current grant holder on this client starts in sync at
    # v1 - nothing to reconcile yet, so no pending-change banner for anyone.
    grant_holders = await db.scalars(
        select(ClientAccessGrant.user_id).where(ClientAccessGrant.client_id == client_id)
    )
    for holder_id in grant_holders:
        db.add(ResourceUserState(resource_id=resource.id, user_id=holder_id, current_version_id=version.id))

    await db.commit()
    await db.refresh(resource)
    return await _resource_out(resource, current_user, db)


@router.get("/clients/{client_id}/resources", response_model=list[ResourceOut])
async def list_resources(
    client_id: uuid.UUID, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)
) -> list[ResourceOut]:
    await get_client_grant(client_id, current_user, db)
    resources = await db.scalars(
        select(Resource).where(Resource.client_id == client_id, Resource.status == ResourceStatus.active)
    )
    return [await _resource_out(r, current_user, db) for r in resources]


@router.get("/resources/{resource_id}", response_model=ResourceOut)
async def get_resource(
    resource_id: uuid.UUID, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)
) -> ResourceOut:
    resource = await _get_active_resource(resource_id, current_user, db)
    return await _resource_out(resource, current_user, db)


@router.delete("/resources/{resource_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_resource(
    resource_id: uuid.UUID, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)
) -> None:
    """Real deletion - only the resource's owner or a superadmin may call this.
    Moves the resource to pending_delete (never hard-deleted) and out of every
    grant holder's view immediately. Any other grant holder gets a 403 pointing
    them at POST .../hide instead, which only affects their own view."""
    resource = await _get_active_resource(resource_id, current_user, db)
    if resource.created_by_user_id != current_user.id and current_user.role != UserRole.admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the resource owner or a superadmin can delete it for everyone - use POST /hide to remove it from just your own view",
        )
    resource.status = ResourceStatus.pending_delete
    resource.deleted_by_user_id = current_user.id
    resource.deleted_at = datetime.now(timezone.utc)
    await db.commit()


async def _get_or_create_state(resource: Resource, user: User, db: AsyncSession) -> ResourceUserState:
    state = await db.get(ResourceUserState, (resource.id, user.id))
    if state is None:
        state = ResourceUserState(resource_id=resource.id, user_id=user.id, current_version_id=resource.latest_version_id)
        db.add(state)
    return state


@router.post("/resources/{resource_id}/hide", status_code=status.HTTP_204_NO_CONTENT)
async def hide_resource(
    resource_id: uuid.UUID, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)
) -> None:
    resource = await _get_active_resource(resource_id, current_user, db)
    state = await _get_or_create_state(resource, current_user, db)
    state.hidden_at = datetime.now(timezone.utc)
    await db.commit()


@router.post("/resources/{resource_id}/unhide", status_code=status.HTTP_204_NO_CONTENT)
async def unhide_resource(
    resource_id: uuid.UUID, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)
) -> None:
    resource = await _get_active_resource(resource_id, current_user, db)
    state = await _get_or_create_state(resource, current_user, db)
    state.hidden_at = None
    await db.commit()


@router.post("/resources/{resource_id}/versions", response_model=ResourceOut)
async def create_resource_version(
    resource_id: uuid.UUID,
    body: ResourceVersionCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ResourceOut:
    resource = await _get_active_resource(resource_id, current_user, db)

    version = ResourceVersion(
        resource_id=resource.id,
        ciphertext=b64decode(body.ciphertext),
        nonce=b64decode(body.nonce),
        changed_by_user_id=current_user.id,
    )
    db.add(version)
    await db.flush()

    resource.latest_version_id = version.id

    # Only the editor's own pointer advances - everyone else's stays put, which is
    # exactly what surfaces the pending-change banner for them.
    state = await _get_or_create_state(resource, current_user, db)
    state.current_version_id = version.id
    state.last_seen_version_id = version.id

    await db.commit()
    await db.refresh(resource)
    return await _resource_out(resource, current_user, db)


@router.get("/resources/{resource_id}/versions", response_model=list[ResourceVersionOut])
async def list_resource_versions(
    resource_id: uuid.UUID, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)
) -> list[ResourceVersionOut]:
    resource = await _get_active_resource(resource_id, current_user, db)
    versions = await db.scalars(
        select(ResourceVersion).where(ResourceVersion.resource_id == resource.id).order_by(ResourceVersion.created_at)
    )
    return [_version_out(v) for v in versions]


@router.get("/resources/{resource_id}/state", response_model=ResourceStateOut)
async def get_resource_state(
    resource_id: uuid.UUID, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)
) -> ResourceStateOut:
    resource = await _get_active_resource(resource_id, current_user, db)
    state = await db.get(ResourceUserState, (resource.id, current_user.id))
    return ResourceStateOut(
        current_version_id=state.current_version_id if state else resource.latest_version_id,
        last_seen_version_id=state.last_seen_version_id if state else None,
        latest_version_id=resource.latest_version_id,
    )


@router.post("/resources/{resource_id}/accept", response_model=ResourceStateOut)
async def accept_resource_change(
    resource_id: uuid.UUID, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)
) -> ResourceStateOut:
    resource = await _get_active_resource(resource_id, current_user, db)
    state = await _get_or_create_state(resource, current_user, db)
    state.current_version_id = resource.latest_version_id
    state.last_seen_version_id = resource.latest_version_id
    await db.commit()
    return ResourceStateOut(
        current_version_id=state.current_version_id,
        last_seen_version_id=state.last_seen_version_id,
        latest_version_id=resource.latest_version_id,
    )


@router.post("/resources/{resource_id}/ignore", response_model=ResourceStateOut)
async def ignore_resource_change(
    resource_id: uuid.UUID, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)
) -> ResourceStateOut:
    resource = await _get_active_resource(resource_id, current_user, db)
    state = await _get_or_create_state(resource, current_user, db)
    # Only dismisses the banner for this version - current_version_id is untouched,
    # so the divergent value genuinely persists until an explicit accept.
    state.last_seen_version_id = resource.latest_version_id
    await db.commit()
    return ResourceStateOut(
        current_version_id=state.current_version_id,
        last_seen_version_id=state.last_seen_version_id,
        latest_version_id=resource.latest_version_id,
    )


@router.post("/resources/{resource_id}/notes", response_model=ResourceNoteOut)
async def create_resource_note(
    resource_id: uuid.UUID,
    body: ResourceNoteCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ResourceNoteOut:
    resource = await _get_active_resource(resource_id, current_user, db)
    note = ResourceNote(
        resource_id=resource.id,
        author_user_id=current_user.id,
        ciphertext=b64decode(body.ciphertext),
        nonce=b64decode(body.nonce),
    )
    db.add(note)
    await db.commit()
    await db.refresh(note)
    return ResourceNoteOut(
        id=note.id, author_user_id=note.author_user_id, ciphertext=b64encode(note.ciphertext), nonce=b64encode(note.nonce), created_at=note.created_at
    )


@router.get("/resources/{resource_id}/notes", response_model=list[ResourceNoteOut])
async def list_resource_notes(
    resource_id: uuid.UUID, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)
) -> list[ResourceNoteOut]:
    resource = await _get_active_resource(resource_id, current_user, db)
    notes = await db.scalars(
        select(ResourceNote).where(ResourceNote.resource_id == resource.id).order_by(ResourceNote.created_at)
    )
    return [
        ResourceNoteOut(
            id=n.id, author_user_id=n.author_user_id, ciphertext=b64encode(n.ciphertext), nonce=b64encode(n.nonce), created_at=n.created_at
        )
        for n in notes
    ]
