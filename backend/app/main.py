from binascii import Error as BinasciiError

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from sqlalchemy.exc import IntegrityError

from app.api.v1 import admin, agent, auth, clients, invites, resources, timeline, tokens, users
from app.core.config import settings
from app.core.limiter import limiter

app = FastAPI(title="Infrawarden API")

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.exception_handler(BinasciiError)
async def binascii_error_handler(request: Request, exc: BinasciiError) -> JSONResponse:
    return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"detail": "Invalid base64 encoding"})


@app.exception_handler(IntegrityError)
async def integrity_error_handler(request: Request, exc: IntegrityError) -> JSONResponse:
    # A safety net for races that slip past an endpoint's own pre-check (e.g. two
    # concurrent requests both passing an "already exists" check before either
    # commits) - translates a raw constraint violation into a clean 409 instead
    # of an unstructured 500, without needing bespoke try/except at every
    # insert site that has a uniqueness constraint.
    return JSONResponse(
        status_code=status.HTTP_409_CONFLICT,
        content={"detail": "Conflict - this may already exist or reference something that no longer does"},
    )

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
