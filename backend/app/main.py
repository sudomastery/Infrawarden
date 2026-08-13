from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.api.v1 import admin, agent, auth, clients, invites, resources, timeline, tokens, users
from app.core.config import settings
from app.core.limiter import limiter

app = FastAPI(title="Infrawarden API")

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api/v1")
app.include_router(invites.router, prefix="/api/v1")
app.include_router(users.router, prefix="/api/v1")
app.include_router(clients.router, prefix="/api/v1")
app.include_router(resources.router, prefix="/api/v1")
app.include_router(admin.router, prefix="/api/v1")
app.include_router(tokens.router, prefix="/api/v1")
app.include_router(agent.router, prefix="/api/v1")
app.include_router(timeline.router, prefix="/api/v1")


@app.get("/api/v1/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
