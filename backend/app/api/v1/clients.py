import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_client_grant, get_current_user
from app.core.encoding import b64decode, b64encode
from app.db.session import get_db
from app.models.client import Client
from app.models.client_access_grant import ClientAccessGrant
from app.models.user import User, UserRole
from app.schemas.client import ClientCreate, ClientDetail, ClientOut

router = APIRouter(prefix="/clients", tags=["clients"])


@router.post("", response_model=ClientDetail)
async def create_client(
    body: ClientCreate, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)
) -> ClientDetail:
    grant_user_ids = {g.user_id for g in body.grants}
    if current_user.id not in grant_user_ids:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Must include a grant for yourself")

    other_ids = grant_user_ids - {current_user.id}
    if other_ids:
        admins = await db.scalars(select(User).where(User.id.in_(other_ids), User.role == UserRole.admin))
        admin_ids = {u.id for u in admins}
        if admin_ids != other_ids:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Only the creator and current superadmins may receive a grant at creation time",
            )

    client = Client(name=body.name, description=body.description, created_by_user_id=current_user.id)
    db.add(client)
    await db.flush()

    caller_wrapped_key: str | None = None
    for grant_in in body.grants:
        db.add(
            ClientAccessGrant(
                client_id=client.id,
                user_id=grant_in.user_id,
                wrapped_data_key=b64decode(grant_in.wrapped_data_key),
                granted_by_user_id=current_user.id,
            )
        )
        if grant_in.user_id == current_user.id:
            caller_wrapped_key = grant_in.wrapped_data_key

    await db.commit()
    await db.refresh(client)

    return ClientDetail(
        id=client.id,
        name=client.name,
        description=client.description,
        created_by_user_id=client.created_by_user_id,
        created_at=client.created_at,
        updated_at=client.updated_at,
        wrapped_data_key=caller_wrapped_key,
    )


@router.get("", response_model=list[ClientDetail])
async def list_clients(
    db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)
) -> list[ClientDetail]:
    rows = await db.execute(
        select(Client, ClientAccessGrant.wrapped_data_key)
        .join(ClientAccessGrant, ClientAccessGrant.client_id == Client.id)
        .where(ClientAccessGrant.user_id == current_user.id)
    )
    return [
        ClientDetail(
            id=client.id,
            name=client.name,
            description=client.description,
            created_by_user_id=client.created_by_user_id,
            created_at=client.created_at,
            updated_at=client.updated_at,
            wrapped_data_key=b64encode(wrapped_data_key),
        )
        for client, wrapped_data_key in rows.all()
    ]


@router.get("/{client_id}", response_model=ClientDetail)
async def get_client(
    client_id: uuid.UUID, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)
) -> ClientDetail:
    grant = await get_client_grant(client_id, current_user, db)
    client = await db.get(Client, client_id)
    if client is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client not found")

    return ClientDetail(
        id=client.id,
        name=client.name,
        description=client.description,
        created_by_user_id=client.created_by_user_id,
        created_at=client.created_at,
        updated_at=client.updated_at,
        wrapped_data_key=b64encode(grant.wrapped_data_key),
    )


@router.delete("/{client_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_client(
    client_id: uuid.UUID, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)
) -> None:
    await get_client_grant(client_id, current_user, db)
    client = await db.get(Client, client_id)
    if client is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client not found")
    if client.created_by_user_id != current_user.id and current_user.role != UserRole.admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only the client owner or a superadmin can delete it")
    await db.delete(client)
    await db.commit()
