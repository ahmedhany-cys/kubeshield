"""FastAPI application factory."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from kubeshield import __version__, audit
from kubeshield.config import get_settings
from kubeshield.db import create_schema, get_engine, init_engine, session_scope
from kubeshield.models import ImageScan, ResponseAction, SimulationRun, User, utcnow
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
        fail_interrupted_work(db)


INTERRUPTED = "interrupted by an API restart before it finished"


def fail_interrupted_work(db: Session) -> dict[str, int]:
    """Close out work a previous process left in flight.

    Simulations, scans and response actions run in background threads of the single API replica, so any
    row still marked in progress at startup belongs to a process that no longer exists. Left as is, a stale
    simulation blocks every later run and a stale scan blocks rescans of its image. Response actions are
    marked failed, never re-executed: an approved containment step is not replayed without a human.
    """
    now = utcnow()
    counts = {"simulations": 0, "scans": 0, "responses": 0}
    for run in db.scalars(select(SimulationRun).where(SimulationRun.status == "running")):
        run.status, run.outcome, run.error, run.finished_at = "error", "error", INTERRUPTED, now
        counts["simulations"] += 1
    for scan in db.scalars(select(ImageScan).where(ImageScan.status.in_(("queued", "running")))):
        scan.status, scan.error, scan.finished_at = "failed", INTERRUPTED, now
        counts["scans"] += 1
    for action in db.scalars(select(ResponseAction).where(ResponseAction.status.in_(("approved", "executing")))):
        # An action caught mid-execution may have partly changed the cluster; the operator must check.
        action.error = INTERRUPTED + ("; check the target, the action may have partly applied"
                                      if action.status == "executing" else "; request it again if still needed")
        action.status, action.completed_at = "failed", now
        audit.record(db, "system", "response.failed", response_engine.target_label(action),
                     incident_id=action.incident_id,
                     details={"action_id": action.id, "action": action.action_type, "error": action.error})
        counts["responses"] += 1
    if any(counts.values()):
        log.warning("marked interrupted work as failed: %s", counts)
        audit.record(db, "system", "system.interrupted_work_failed", "kubeshield-api", details=counts)
    return counts


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
