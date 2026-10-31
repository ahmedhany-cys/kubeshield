"""Correlation of security events into incidents."""

from __future__ import annotations

import logging
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from kubeshield import audit, settings_store, severity
from kubeshield.catalog import DETECTIONS_BY_ID
from kubeshield.config import get_settings
from kubeshield.models import Incident, SecurityEvent

log = logging.getLogger(__name__)

ACTIVE_STATUSES = ("open", "investigating", "contained")
STATUSES = ("open", "investigating", "contained", "resolved", "false_positive")
# Three or more distinct detections on one workload inside the correlation
# window look like a hands-on-keyboard attack chain: never rate it below high.
CHAIN_RULE_THRESHOLD = 3


def _workload_from_pod(pod: str | None) -> str | None:
    """Best-effort Deployment name from a pod name (name-<rs hash>-<pod hash>)."""
    if not pod:
        return None
    parts = pod.rsplit("-", 2)
    return parts[0] if len(parts) == 3 and len(parts[2]) == 5 else pod


def _title(rules: list[str], namespace: str | None, pod: str | None) -> str:
    where = f"{namespace}/{pod}" if pod else (namespace or "cluster")
    if len(rules) == 1:
        det = DETECTIONS_BY_ID.get(rules[0])
        name = det.name if det else rules[0]
        return f"{name} in {where}"
    return f"{len(rules)} correlated detections in {where}"


def correlate(db: Session, event: SecurityEvent) -> Incident | None:
    if not severity.at_least(event.severity, settings_store.get(db, "incidents.min_severity")):
        return None
    window = timedelta(minutes=get_settings().incident_window_minutes)
    rule_key = event.rule_id or event.rule

    incident = db.scalar(
        select(Incident)
        .where(
            Incident.status.in_(ACTIVE_STATUSES),
            Incident.namespace == event.namespace,
            Incident.pod == event.pod,
            Incident.last_seen >= event.timestamp - window,
        )
        .order_by(Incident.last_seen.desc())
        .limit(1)
    )
    created = incident is None
    if incident is None:
        incident = Incident(
            title="",
            status="open",
            severity=event.severity,
            namespace=event.namespace,
            pod=event.pod,
            workload=_workload_from_pod(event.pod),
            rules=[],
            techniques=[],
            event_count=0,
            first_seen=event.timestamp,
            last_seen=event.timestamp,
        )
        db.add(incident)
        db.flush()

    rules = list(incident.rules or [])
    if rule_key not in rules:
        rules.append(rule_key)
    techniques = list(incident.techniques or [])
    for t in event.techniques or []:
        if t not in techniques:
            techniques.append(t)
    new_severity = severity.max_severity(incident.severity, event.severity)
    if len(rules) >= CHAIN_RULE_THRESHOLD:
        new_severity = severity.max_severity(new_severity, "high")

    incident.rules = rules
    incident.techniques = techniques
    incident.severity = new_severity
    incident.event_count = (incident.event_count or 0) + 1
    incident.first_seen = min(incident.first_seen, event.timestamp)
    incident.last_seen = max(incident.last_seen, event.timestamp)
    incident.title = _title(rules, incident.namespace, incident.pod)
    incident.summary = (
        f"{incident.event_count} event(s) from {len(rules)} detection(s); "
        f"latest: {event.rule} ({event.severity})."
    )
    event.incident_id = incident.id
    db.flush()

    if created:
        audit.record(db, "system", "incident.created", incident.title, incident_id=incident.id,
                     details={"trigger_event": event.id, "severity": incident.severity})

    from kubeshield.response import engine  # local import avoids a cycle

    engine.on_incident_event(db, incident, event)
    return incident


def set_status(db: Session, incident: Incident, status: str, actor: str, note: str | None = None) -> None:
    if status not in STATUSES:
        raise ValueError(f"invalid status {status}")
    previous = incident.status
    incident.status = status
    if status in ("resolved", "false_positive"):
        from kubeshield.models import utcnow

        incident.resolved_at = utcnow()
    audit.record(db, actor, "incident.status_changed", f"incident:{incident.id}", incident_id=incident.id,
                 details={"from": previous, "to": status, "note": note})
