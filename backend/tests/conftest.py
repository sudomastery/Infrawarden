import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.limiter import limiter
from app.db.base import Base
from app.db.session import async_session_factory, engine
from app.main import app

# Rate limiting is real production behavior, but tests routinely issue far more
# than 10 logins/minute against the same 127.0.0.1 identity when exercising many
# scenarios back to back - disable it here rather than let it flake tests.
limiter.enabled = False


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
