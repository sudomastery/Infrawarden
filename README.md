# Infrawarden

A self-documenting infrastructure credential vault, organized per client/environment, that lets
authorized users hand an AI coding agent (Claude Code) scoped, time-limited access to real credentials
without ever pasting plaintext into a chat.

See `docs/ARCHITECTURE.md` for how the encryption and access model actually works.

## Local development

Requires Docker and Docker Compose.

```bash
cp .env.example .env
# edit .env with real secrets before doing anything beyond local dev

docker compose up --build
```

- Backend: http://localhost:8000 (health check at `/api/v1/health`)
- Frontend: http://localhost:5173
- Postgres: localhost:5432

### Backend only (without Docker)

```bash
cd backend
pip install -e ".[dev]"
alembic upgrade head
uvicorn app.main:app --reload
```

### Frontend only (without Docker)

```bash
cd frontend
npm install
npm run dev
```

## Repo layout

- `backend/` - FastAPI + SQLAlchemy + Alembic API
- `frontend/` - React + TailwindCSS web vault
- `mcp-server/` - MCP server that plugs an Infrawarden API key into Claude Code
- `docs/` - architecture reference
