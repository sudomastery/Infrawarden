import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import Base
from app.db.session import async_session_factory, engine
from app.main import app


@pytest.fixture(autouse=True)
async def _reset_schema():
    # Function-scoped (not session-scoped): each test gets a clean database, since
    # several tests seed the same fixed admin email and would collide otherwise.
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture
async def db_session() -> AsyncSession:
    async with async_session_factory() as session:
        yield session
