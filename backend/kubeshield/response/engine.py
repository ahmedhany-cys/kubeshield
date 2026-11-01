"""Response engine: playbook evaluation, approval workflow and safe execution."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from kubernetes.client import ApiException
from sqlalchemy import select
from sqlalchemy.orm import Session

from kubeshield import audit, settings_store, severity
from kubeshield.db import after_commit, session_scope
from kubeshield.k8s.client import KubeUnavailable, LabGuardError, kube
from kubeshield.models import Incident, Playbook, ResponseAction, SecurityEvent, utcnow
from kubeshield.response.actions import ACTIONS, owning_deployment

log = logging.getLogger(__name__)

MODES = ("alert_only", "approval", "auto")
TERMINAL = ("succeeded", "failed", "rejected", "refused", "alerted")
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="ks-response")
# Tests set this to run executions inline.
SYNCHRONOUS = False

DEFAULT_PLAYBOOKS: tuple[dict[str, Any], ...] = (
    {
        "name": "Quarantine pods with credential access",
        "description": "Service account token or credential store read: isolate the pod from the network.",
        "match_rule_ids": ["ks.003", "ks.004"],
        "min_severity": "high",
        "action_type": "isolate_pod",
        "mode": "approval",
    },
    {
        "name": "Quarantine pods with host or privilege escalation activity",
        "description": "Host path access, setuid planting or execution of dropped binaries.",
        "match_rule_ids": ["ks.005", "ks.006", "ks.008"],
        "min_severity": "critical",
        "action_type": "isolate_pod",
        "mode": "approval",
    },
    {
        "name": "Delete compromised lab pod",
        "description": "Capture forensics and delete the pod after an analyst approves.",
        "match_rule_ids": ["ks.004", "ks.006", "ks.008"],
        "min_severity": "critical",
        "action_type": "delete_pod",
        "mode": "approval",
    },
    {
        "name": "Notify on interactive shells",
        "description": "Record shell and tool execution without changing the workload.",
        "match_rule_ids": ["ks.001", "ks.002"],
        "min_severity": "medium",
        "action_type": "alert_only",
        "mode": "alert_only",
    },
)


def seed_playbooks(db: Session) -> None:
    if db.scalar(select(Playbook.id).limit(1)) is not None:
        return
    for pb in DEFAULT_PLAYBOOKS:
        db.add(Playbook(**pb))
    db.flush()


def _matches(pb: Playbook, event: SecurityEvent) -> bool:
    if not pb.enabled:
        return False
    if pb.match_rule_ids and (event.rule_id or event.rule) not in pb.match_rule_ids:
        return False
    return severity.at_least(event.severity, pb.min_severity)


def on_incident_event(db: Session, incident: Incident, event: SecurityEvent) -> list[ResponseAction]:
    """Evaluate playbooks for an event that was attached to an incident."""
    created: list[ResponseAction] = []
    if not incident.namespace or not incident.pod:
        return created
    for pb in db.scalars(select(Playbook).where(Playbook.enabled.is_(True)).order_by(Playbook.id)):
        if not _matches(pb, event):
            continue
        already = db.scalar(
            select(ResponseAction.id).where(
                ResponseAction.incident_id == incident.id,
                ResponseAction.action_type == pb.action_type,
                ResponseAction.status.notin_(("failed", "rejected", "refused")),
            )
        )
        if already:
            continue
        created.append(_create_from_playbook(db, pb, incident, event))
    return created


def _create_from_playbook(db: Session, pb: Playbook, incident: Incident, event: SecurityEvent) -> ResponseAction:
    spec = ACTIONS[pb.action_type]
    mode = pb.mode
    reason = f"Playbook '{pb.name}' matched {event.rule_id or event.rule} ({event.severity})."
    if mode == "auto":
        if not settings_store.get(db, "response.auto_enabled"):
            mode, reason = "approval", reason + " Automatic response is disabled globally; approval required."
        elif spec.destructive and not settings_store.get(db, "response.auto_destructive_enabled"):
            mode, reason = "approval", reason + " Destructive actions are never automatic by default."
    action = ResponseAction(
        incident_id=incident.id,
        trigger_event_id=event.id,
        playbook_id=pb.id,
        action_type=pb.action_type,
        mode=mode,
        status="pending_approval" if mode == "approval" else ("alerted" if mode == "alert_only" else "approved"),
        target_namespace=incident.namespace or "",
        target_kind=spec.target_kind,
        target_name=incident.pod or "",
        reason=reason,
        requested_by="playbook",
    )
    if mode == "alert_only":
        action.completed_at = utcnow()
        action.result = {"changed": False, "message": "Alert-only playbook: no cluster change."}
    db.add(action)
    db.flush()
    audit.record(db, "playbook", f"response.{action.status}", target_label(action), incident_id=incident.id,
                 details={"action_id": action.id, "action": action.action_type, "playbook": pb.name,
                          "trigger_event": event.id, "mode": mode})
    if mode == "auto":
        schedule(db, action.id)
    return action


def target_label(a: ResponseAction) -> str:
    return f"{a.target_kind}/{a.target_namespace}/{a.target_name}"


def request_manual(db: Session, incident: Incident | None, action_type: str, namespace: str, name: str,
                   actor: str, reason: str) -> ResponseAction:
    if action_type not in ACTIONS:
        raise ValueError(f"unknown action {action_type}")
    spec = ACTIONS[action_type]
    action = ResponseAction(
        incident_id=incident.id if incident else None,
        action_type=action_type,
        mode="manual",
        status="approved",
        target_namespace=namespace,
        target_kind=spec.target_kind,
        target_name=name,
        reason=reason or "Manual response requested by analyst.",
        requested_by=actor,
        decided_by=actor,
        decided_at=utcnow(),
    )
    db.add(action)
    db.flush()
    audit.record(db, actor, "response.requested", target_label(action), incident_id=action.incident_id,
                 details={"action_id": action.id, "action": action_type, "reason": action.reason})
    return action


def decide(db: Session, action: ResponseAction, approve: bool, actor: str, note: str | None = None) -> None:
    if action.status != "pending_approval":
        raise ValueError(f"action is {action.status}, not pending approval")
    action.status = "approved" if approve else "rejected"
    action.decided_by = actor
    action.decided_at = utcnow()
    if not approve:
        action.completed_at = utcnow()
    audit.record(db, actor, "response.approved" if approve else "response.rejected", target_label(action),
                 incident_id=action.incident_id, details={"action_id": action.id, "note": note})


def schedule(db: Session, action_id: str) -> None:
    """Execute the action once the current transaction has committed."""
    after_commit(db, lambda: execute(action_id) if SYNCHRONOUS else _executor.submit(execute, action_id))


def execute(action_id: str) -> None:
    """Run an approved action in its own transaction and record every outcome."""
    with session_scope() as db:
        action = db.get(ResponseAction, action_id)
        if action is None or action.status != "approved":
            return
        action.status = "executing"
        action.executed_at = utcnow()
        db.flush()
        spec = ACTIONS[action.action_type]
        ctx: dict[str, Any] = {"incident_id": action.incident_id}
        namespace, name = action.target_namespace, action.target_name
        try:
            kube.require_lab_namespace(namespace)
            if spec.target_kind == "Deployment" and action.target_kind == "Deployment":
                deployment = owning_deployment(namespace, name) if _is_pod(namespace, name) else name
                if not deployment:
                    raise RuntimeError(f"pod {name} is not owned by a Deployment")
                action.result = {"resolved_from_pod": name} if deployment != name else {}
                action.target_name = name = deployment
            result = spec.execute(namespace, name, ctx)
            action.result = {**(action.result or {}), **result}
            ctx["result"] = action.result
            verification = spec.verify(namespace, name, ctx)
            action.verification = verification
            action.status = "succeeded" if verification.get("verified") else "failed"
            if not verification.get("verified"):
                action.error = "post-action verification failed"
            if action.incident_id and action.status == "succeeded" and action.action_type in (
                "isolate_pod", "delete_pod", "scale_to_zero", "contain_namespace"
            ):
                inc = db.get(Incident, action.incident_id)
                if inc and inc.status in ("open", "investigating"):
                    inc.status = "contained"
                    audit.record(db, "response-engine", "incident.status_changed", f"incident:{inc.id}",
                                 incident_id=inc.id, details={"to": "contained", "by_action": action.id})
        except LabGuardError as exc:
            action.status, action.error = "refused", str(exc)
        except (ApiException, KubeUnavailable, RuntimeError, ValueError) as exc:
            action.status = "failed"
            action.error = f"HTTP {exc.status}: {exc.reason}" if isinstance(exc, ApiException) else str(exc)
        except Exception as exc:  # noqa: BLE001 - never lose an outcome
            log.exception("response action %s crashed", action_id)
            action.status, action.error = "failed", f"unexpected error: {exc}"
        action.completed_at = utcnow()
        audit.record(db, "response-engine", f"response.{action.status}", target_label(action),
                     incident_id=action.incident_id,
                     details={"action_id": action.id, "action": action.action_type, "error": action.error,
                              "verified": (action.verification or {}).get("verified")})


def _is_pod(namespace: str, name: str) -> bool:
    try:
        kube.core.read_namespaced_pod(name, namespace)
        return True
    except ApiException:
        return False
