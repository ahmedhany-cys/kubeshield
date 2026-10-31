"""Authentication, ingestion, events, incidents and response APIs."""

from __future__ import annotations

import json
import logging
from datetime import timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from kubeshield import audit, incidents, ingest
from kubeshield.api import serializers as ser
from kubeshield.config import get_settings
from kubeshield.db import get_db
from kubeshield.models import AuditLog, Incident, Playbook, ResponseAction, SecurityEvent, utcnow
from kubeshield.response import engine
from kubeshield.response.actions import ACTIONS
from kubeshield.security import (
    SESSION_COOKIE,
    Principal,
    authenticate,
    current_user,
    issue_token,
    login_limiter,
    require_role,
    verify_ingest_token,
)
from kubeshield.severity import SEVERITIES

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1")
DB = Annotated[Session, Depends(get_db)]
Viewer = Annotated[Principal, Depends(require_role("viewer"))]
Responder = Annotated[Principal, Depends(require_role("responder"))]
Admin = Annotated[Principal, Depends(require_role("admin"))]

K8S_NAME = r"^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$"
MAX_INGEST_BYTES = 1_000_000


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


# --------------------------------------------------------------------------- auth
class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


@router.post("/auth/login")
def login(body: LoginIn, request: Request, response: Response, db: DB) -> dict[str, Any]:
    key = f"{client_ip(request)}|{body.username.lower()}"
    if login_limiter.blocked(key):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too many failed attempts; try again later")
    user = authenticate(db, body.username, body.password)
    if user is None:
        login_limiter.fail(key)
        audit.record(db, body.username[:64], "auth.login_failed", source_ip=client_ip(request))
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid username or password")
    login_limiter.reset(key)
    user.last_login_at = utcnow()
    token = issue_token(user)
    s = get_settings()
    response.set_cookie(SESSION_COOKIE, token, httponly=True, secure=s.cookie_secure, samesite="strict",
                        max_age=s.session_ttl_minutes * 60, path="/")
    audit.record(db, user.username, "auth.login", source_ip=client_ip(request))
    return {"username": user.username, "role": user.role}


@router.post("/auth/logout")
def logout(response: Response, principal: Annotated[Principal, Depends(current_user)], db: DB) -> dict[str, str]:
    response.delete_cookie(SESSION_COOKIE, path="/")
    audit.record(db, principal.username, "auth.logout")
    return {"status": "logged out"}


@router.get("/auth/me")
def me(principal: Annotated[Principal, Depends(current_user)]) -> dict[str, str]:
    return {"username": principal.username, "role": principal.role}


# --------------------------------------------------------------------------- ingestion
@router.post("/ingest/falco", status_code=202, dependencies=[Depends(verify_ingest_token)])
async def ingest_falco(request: Request, db: DB) -> dict[str, Any]:
    body = await request.body()
    if len(body) > MAX_INGEST_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "payload too large")
    try:
        payload = json.loads(body)
        fields = ingest.normalize_falco(payload)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"invalid Falco payload: {exc}") from exc
    event, created = ingest.store_event(db, fields)
    return {"id": event.id, "created": created, "incident_id": event.incident_id}


# --------------------------------------------------------------------------- events
@router.get("/events")
def list_events(
    db: DB, _: Viewer,
    severity: Annotated[list[str] | None, Query()] = None,
    source: str | None = None,
    namespace: str | None = None,
    rule_id: str | None = None,
    q: Annotated[str | None, Query(max_length=200)] = None,
    since_hours: Annotated[int | None, Query(ge=1, le=24 * 90)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict[str, Any]:
    stmt = select(SecurityEvent)
    if severity:
        stmt = stmt.where(SecurityEvent.severity.in_([s for s in severity if s in SEVERITIES]))
    if source:
        stmt = stmt.where(SecurityEvent.source == source)
    if namespace:
        stmt = stmt.where(SecurityEvent.namespace == namespace)
    if rule_id:
        stmt = stmt.where(SecurityEvent.rule_id == rule_id)
    if since_hours:
        stmt = stmt.where(SecurityEvent.timestamp >= utcnow() - timedelta(hours=since_hours))
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(SecurityEvent.message.ilike(like), SecurityEvent.rule.ilike(like),
                              SecurityEvent.pod.ilike(like), SecurityEvent.namespace.ilike(like)))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.order_by(SecurityEvent.timestamp.desc()).offset(offset).limit(limit)).all()
    return {"total": total, "items": [ser.event(e) for e in rows]}


@router.get("/events/{event_id}")
def get_event(event_id: str, db: DB, _: Viewer) -> dict[str, Any]:
    e = db.get(SecurityEvent, event_id)
    if e is None:
        raise HTTPException(404, "event not found")
    return ser.event(e, raw=True)


# --------------------------------------------------------------------------- incidents
@router.get("/incidents")
def list_incidents(
    db: DB, _: Viewer,
    status_: Annotated[list[str] | None, Query(alias="status")] = None,
    severity: Annotated[list[str] | None, Query()] = None,
    q: Annotated[str | None, Query(max_length=200)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict[str, Any]:
    stmt = select(Incident)
    if status_:
        stmt = stmt.where(Incident.status.in_(status_))
    if severity:
        stmt = stmt.where(Incident.severity.in_(severity))
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(Incident.title.ilike(like), Incident.pod.ilike(like),
                              Incident.namespace.ilike(like)))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.order_by(Incident.last_seen.desc()).offset(offset).limit(limit)).all()
    return {"total": total, "items": [ser.incident(i) for i in rows]}


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: int, db: DB, _: Viewer) -> dict[str, Any]:
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(404, "incident not found")
    events = db.scalars(select(SecurityEvent).where(SecurityEvent.incident_id == incident_id)
                        .order_by(SecurityEvent.timestamp)).all()
    actions = db.scalars(select(ResponseAction).where(ResponseAction.incident_id == incident_id)
                         .order_by(ResponseAction.requested_at)).all()
    trail = db.scalars(select(AuditLog).where(AuditLog.incident_id == incident_id)
                       .order_by(AuditLog.timestamp)).all()
    return {**ser.incident(inc), "events": [ser.event(e) for e in events],
            "actions": [ser.action(a) for a in actions], "audit_trail": [ser.audit(a) for a in trail]}


class IncidentStatusIn(BaseModel):
    status: Literal["open", "investigating", "contained", "resolved", "false_positive"]
    note: str | None = Field(None, max_length=2000)


@router.post("/incidents/{incident_id}/status")
def update_incident_status(incident_id: int, body: IncidentStatusIn, db: DB, p: Responder) -> dict[str, Any]:
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(404, "incident not found")
    incidents.set_status(db, inc, body.status, p.username, body.note)
    return ser.incident(inc)


# --------------------------------------------------------------------------- responses
@router.get("/responses/actions")
def action_catalog(_: Viewer) -> list[dict[str, Any]]:
    return [{"type": a.type, "title": a.title, "description": a.description, "target_kind": a.target_kind,
             "destructive": a.destructive} for a in ACTIONS.values()]


@router.get("/responses")
def list_responses(
    db: DB, _: Viewer,
    status_: Annotated[list[str] | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> dict[str, Any]:
    stmt = select(ResponseAction)
    if status_:
        stmt = stmt.where(ResponseAction.status.in_(status_))
    rows = db.scalars(stmt.order_by(ResponseAction.requested_at.desc()).limit(limit)).all()
    return {"total": len(rows), "items": [ser.action(a) for a in rows]}


class ManualResponseIn(BaseModel):
    action_type: str = Field(max_length=32)
    namespace: str = Field(pattern=K8S_NAME, max_length=63)
    name: str = Field(pattern=K8S_NAME, max_length=253)
    incident_id: int | None = None
    reason: str = Field("", max_length=2000)


@router.post("/responses", status_code=202)
def create_response(body: ManualResponseIn, request: Request, db: DB, p: Responder) -> dict[str, Any]:
    if body.action_type not in ACTIONS:
        raise HTTPException(422, f"unknown action_type; expected one of {sorted(ACTIONS)}")
    if ACTIONS[body.action_type].destructive and not p.has("admin"):
        raise HTTPException(403, "destructive actions require the admin role")
    inc = db.get(Incident, body.incident_id) if body.incident_id else None
    if body.incident_id and inc is None:
        raise HTTPException(404, "incident not found")
    action = engine.request_manual(db, inc, body.action_type, body.namespace, body.name, p.username,
                                   body.reason)
    engine.schedule(db, action.id)
    return ser.action(action)


class DecisionIn(BaseModel):
    approve: bool
    note: str | None = Field(None, max_length=2000)


@router.post("/responses/{action_id}/decision")
def decide_response(action_id: str, body: DecisionIn, db: DB, p: Responder) -> dict[str, Any]:
    action = db.get(ResponseAction, action_id)
    if action is None:
        raise HTTPException(404, "action not found")
    if body.approve and ACTIONS[action.action_type].destructive and not p.has("admin"):
        raise HTTPException(403, "approving destructive actions requires the admin role")
    try:
        engine.decide(db, action, body.approve, p.username, body.note)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    if body.approve:
        engine.schedule(db, action.id)
    return ser.action(action)


@router.get("/responses/{action_id}")
def get_response(action_id: str, db: DB, _: Viewer) -> dict[str, Any]:
    action = db.get(ResponseAction, action_id)
    if action is None:
        raise HTTPException(404, "action not found")
    return ser.action(action)


# --------------------------------------------------------------------------- playbooks
@router.get("/playbooks")
def list_playbooks(db: DB, _: Viewer) -> list[dict[str, Any]]:
    return [ser.playbook(p) for p in db.scalars(select(Playbook).order_by(Playbook.id))]


class PlaybookIn(BaseModel):
    name: str = Field(min_length=3, max_length=128)
    description: str = Field("", max_length=1000)
    enabled: bool = True
    match_rule_ids: list[Annotated[str, Field(max_length=32)]] = Field(default_factory=list, max_length=50)
    min_severity: Literal["critical", "high", "medium", "low", "info"] = "high"
    action_type: str
    mode: Literal["alert_only", "approval", "auto"] = "approval"


def _validate_playbook(body: PlaybookIn) -> None:
    if body.action_type not in ACTIONS or body.action_type.startswith("release_"):
        raise HTTPException(422, "invalid action_type for a playbook")


@router.post("/playbooks", status_code=201)
def create_playbook(body: PlaybookIn, db: DB, p: Admin) -> dict[str, Any]:
    _validate_playbook(body)
    if db.scalar(select(Playbook).where(Playbook.name == body.name)):
        raise HTTPException(409, "a playbook with this name exists")
    pb = Playbook(**body.model_dump())
    db.add(pb)
    db.flush()
    audit.record(db, p.username, "playbook.created", pb.name, details=body.model_dump())
    return ser.playbook(pb)


@router.put("/playbooks/{playbook_id}")
def update_playbook(playbook_id: int, body: PlaybookIn, db: DB, p: Admin) -> dict[str, Any]:
    _validate_playbook(body)
    pb = db.get(Playbook, playbook_id)
    if pb is None:
        raise HTTPException(404, "playbook not found")
    before = ser.playbook(pb)
    for k, v in body.model_dump().items():
        setattr(pb, k, v)
    db.flush()
    audit.record(db, p.username, "playbook.updated", pb.name, details={"before": before, "after": body.model_dump()})
    return ser.playbook(pb)


@router.delete("/playbooks/{playbook_id}", status_code=204)
def delete_playbook(playbook_id: int, db: DB, p: Admin) -> Response:
    pb = db.get(Playbook, playbook_id)
    if pb is None:
        raise HTTPException(404, "playbook not found")
    audit.record(db, p.username, "playbook.deleted", pb.name, details=ser.playbook(pb))
    db.delete(pb)
    return Response(status_code=204)


# --------------------------------------------------------------------------- audit
@router.get("/audit")
def list_audit(
    db: DB, _: Viewer,
    action: str | None = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
) -> list[dict[str, Any]]:
    stmt = select(AuditLog)
    if action:
        stmt = stmt.where(AuditLog.action.startswith(action))
    return [ser.audit(a) for a in db.scalars(stmt.order_by(AuditLog.timestamp.desc()).limit(limit))]
