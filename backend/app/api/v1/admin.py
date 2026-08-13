import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import require_admin
from app.core.encoding import b64encode
from app.db.session import get_db
from app.models.client import Client
from app.models.client_access_grant import ClientAccessGrant
from app.models.resource import Resource, ResourceStatus
from app.models.resource_version import ResourceVersion
from app.models.user import User, UserRole
from app.schemas.access import PromoteResponse
from app.schemas.resource import DeletedResourceOut, ResourceVersionOut

router = APIRouter(prefix="/admin", tags=["admin"])


@router.post("/users/{user_id}/promote", response_model=PromoteResponse)
async def promote_to_admin(
    user_id: uuid.UUID, db: AsyncSession = Depends(get_db), _admin: User = Depends(require_admin)
) -> PromoteResponse:
    """Grants the superadmin role. This does NOT retroactively grant decrypt access
    to existing clients - see docs/ARCHITECTURE.md 'Superadmin access model'. The
    promoting superadmin's browser must still call POST /clients/{id}/access once
    per client returned here (it already holds every client's data key, by the
    same guarantee, so it can do this for all of them in one online session)."""
    target = await db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    target.role = UserRole.admin
    await db.commit()

    all_client_ids = set((await db.scalars(select(Client.id))).all())
    granted_client_ids = set(
        (await db.scalars(select(ClientAccessGrant.client_id).where(ClientAccessGrant.user_id == user_id))).all()
    )
    return PromoteResponse(user_id=user_id, clients_needing_reconciliation=list(all_client_ids - granted_client_ids))


@router.get("/deleted-resources", response_model=list[DeletedResourceOut])
async def list_deleted_resources(
    db: AsyncSession = Depends(get_db), _admin: User = Depends(require_admin)
) -> list[DeletedResourceOut]:
    """Every pending_delete resource across every client - decryptable, since
    superadmins hold a wrapped copy of every client's data key by construction.
    This is the literal mechanism behind 'no credentials are ever lost'."""
    rows = await db.execute(
        select(Resource, Client.name)
        .join(Client, Client.id == Resource.client_id)
        .where(Resource.status == ResourceStatus.pending_delete)
    )
    out = []
    for resource, client_name in rows.all():
        version = await db.get(ResourceVersion, resource.latest_version_id)
        out.append(
            DeletedResourceOut(
                id=resource.id,
                client_id=resource.client_id,
                client_name=client_name,
                resource_type=resource.resource_type,
                created_by_user_id=resource.created_by_user_id,
                deleted_by_user_id=resource.deleted_by_user_id,
                deleted_at=resource.deleted_at,
                latest_version=ResourceVersionOut(
                    id=version.id,
                    changed_by_user_id=version.changed_by_user_id,
                    ciphertext=b64encode(version.ciphertext),
                    nonce=b64encode(version.nonce),
                    created_at=version.created_at,
                ),
            )
        )
    return out


@router.post("/deleted-resources/{resource_id}/restore", status_code=status.HTTP_204_NO_CONTENT)
async def restore_deleted_resource(
    resource_id: uuid.UUID, db: AsyncSession = Depends(get_db), _admin: User = Depends(require_admin)
) -> None:
    resource = await db.get(Resource, resource_id)
    if resource is None or resource.status != ResourceStatus.pending_delete:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Deleted resource not found")
    resource.status = ResourceStatus.active
    resource.deleted_by_user_id = None
    resource.deleted_at = None
    await db.commit()
