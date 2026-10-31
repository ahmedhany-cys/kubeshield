"""Append-only audit trail helpers."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from kubeshield.models import AuditLog


def record(
    db: Session,
    actor: str,
    action: str,
    target: str | None = None,
    *,
    incident_id: int | None = None,
    details: dict[str, Any] | None = None,
    source_ip: str | None = None,
) -> AuditLog:
    entry = AuditLog(
        actor=actor,
        action=action,
        target=target,
        incident_id=incident_id,
        details=details or {},
        source_ip=source_ip,
    )
    db.add(entry)
    db.flush()
    return entry
