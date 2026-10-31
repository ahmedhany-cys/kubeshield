"""FastAPI application factory."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select, text

from kubeshield import __version__, audit
from kubeshield.config import get_settings
from kubeshield.db import create_schema, get_engine, init_engine, session_scope
from kubeshield.models import User
from kubeshield.response import engine as response_engine
from kubeshield.security import hash_password

log = logging.getLogger("kubeshield")
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
CSRF_HEADER = "x-requested-with"
CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


def bootstrap() -> None:
    s = get_settings()
    init_engine(s.database_url)
    create_schema()
    with session_scope() as db:
        if db.scalar(select(User.id).limit(1)) is None:
            if s.admin_password is None:
                log.warning("no users exist and KUBESHIELD_ADMIN_PASSWORD is not set; nobody can log in")
            else:
                db.add(User(username=s.admin_username, password_hash=hash_password(
                    s.admin_password.get_secret_value()), role="admin"))
                audit.record(db, "system", "user.bootstrap_admin_created", s.admin_username)
        response_engine.seed_playbooks(db)


def create_app(start_workers: bool | None = None) -> FastAPI:
    s = get_settings()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        bootstrap()
        run_workers = s.workers_enabled if start_workers is None else start_workers
        if run_workers:
            from kubeshield import workers

            workers.start()
        yield
        if run_workers:
            from kubeshield import workers

            workers.stop()

    app = FastAPI(title="KubeShield", version=__version__, lifespan=lifespan,
                  docs_url="/api/docs", redoc_url=None, openapi_url="/api/openapi.json")

    @app.middleware("http")
    async def hardening(request: Request, call_next):
        # Cookie-authenticated state changes must carry a custom header, which a
        # cross-site form or simple request cannot add (CSRF defence in depth on
        # top of SameSite=Strict cookies). Bearer-token ingestion is exempt.
        if (request.method not in SAFE_METHODS and request.url.path.startswith("/api/")
                and not request.url.path.startswith("/api/v1/ingest/")
                and request.url.path != "/api/v1/auth/login"
                and request.headers.get(CSRF_HEADER) != "kubeshield"):
            return JSONResponse({"detail": "missing X-Requested-With header"}, status_code=403)
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if not request.url.path.startswith("/api/docs"):
            response.headers.setdefault("Content-Security-Policy", CSP)
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    from kubeshield.api import core, platform

    app.include_router(core.router)
    app.include_router(platform.router)

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz", include_in_schema=False)
    def readyz() -> JSONResponse:
        try:
            with get_engine().connect() as conn:
                conn.execute(text("SELECT 1"))
            return JSONResponse({"status": "ready"})
        except Exception:  # noqa: BLE001
            return JSONResponse({"status": "database unavailable"}, status_code=503)

    static = Path(s.static_dir) if s.static_dir else None
    if static and (static / "index.html").exists():
        app.mount("/assets", StaticFiles(directory=static / "assets"), name="assets")

        @app.get("/{path:path}", include_in_schema=False)
        def spa(path: str):
            if path.startswith("api/"):
                return JSONResponse({"detail": "Not Found"}, status_code=404)
            candidate = (static / path).resolve()
            if path and candidate.is_file() and static.resolve() in candidate.parents:
                return FileResponse(candidate)
            return FileResponse(static / "index.html")

    return app
