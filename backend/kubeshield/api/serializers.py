"""Model -> JSON helpers shared by the API routers."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from kubeshield.catalog import DETECTIONS_BY_ID
from kubeshield.models import (
    AuditLog,
    ImageScan,
    Incident,
    NetworkFlow,
    Playbook,
    PolicyViolation,
    PostureFinding,
    ResponseAction,
    SecurityEvent,
    SimulationRun,
)


def iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def event(e: SecurityEvent, *, raw: bool = False) -> dict[str, Any]:
    det = DETECTIONS_BY_ID.get(e.rule_id) if e.rule_id else None
    out = {
        "id": e.id, "source": e.source, "rule": e.rule, "rule_id": e.rule_id,
        "detection": det.name if det else None, "severity": e.severity, "source_priority": e.source_priority,
        "timestamp": iso(e.timestamp), "ingested_at": iso(e.ingested_at), "namespace": e.namespace,
        "pod": e.pod, "container": e.container, "container_id": e.container_id, "image": e.image,
        "node": e.node, "process": e.process, "message": e.message, "evidence": e.evidence, "tags": e.tags,
        "techniques": e.techniques, "recommended_response": e.recommended_response,
        "incident_id": e.incident_id,
    }
    if raw:
        out["raw"] = e.raw
    return out


def incident(i: Incident) -> dict[str, Any]:
    return {
        "id": i.id, "title": i.title, "status": i.status, "severity": i.severity, "namespace": i.namespace,
        "pod": i.pod, "workload": i.workload, "summary": i.summary, "rules": i.rules,
        "techniques": i.techniques, "event_count": i.event_count, "first_seen": iso(i.first_seen),
        "last_seen": iso(i.last_seen), "created_at": iso(i.created_at), "updated_at": iso(i.updated_at),
        "resolved_at": iso(i.resolved_at),
    }


def action(a: ResponseAction) -> dict[str, Any]:
    return {
        "id": a.id, "incident_id": a.incident_id, "trigger_event_id": a.trigger_event_id,
        "playbook_id": a.playbook_id, "action_type": a.action_type, "mode": a.mode, "status": a.status,
        "target": {"namespace": a.target_namespace, "kind": a.target_kind, "name": a.target_name},
        "reason": a.reason, "requested_by": a.requested_by, "decided_by": a.decided_by,
        "requested_at": iso(a.requested_at), "decided_at": iso(a.decided_at), "executed_at": iso(a.executed_at),
        "completed_at": iso(a.completed_at), "result": a.result or None, "verification": a.verification or None,
        "error": a.error,
    }


def playbook(p: Playbook) -> dict[str, Any]:
    return {"id": p.id, "name": p.name, "description": p.description, "enabled": p.enabled,
            "match_rule_ids": p.match_rule_ids, "min_severity": p.min_severity, "action_type": p.action_type,
            "mode": p.mode, "updated_at": iso(p.updated_at)}


def audit(a: AuditLog) -> dict[str, Any]:
    return {"id": a.id, "timestamp": iso(a.timestamp), "actor": a.actor, "action": a.action,
            "target": a.target, "incident_id": a.incident_id, "details": a.details, "source_ip": a.source_ip}


def finding(f: PostureFinding) -> dict[str, Any]:
    return {"id": f.id, "check_id": f.check_id, "title": f.title, "category": f.category,
            "severity": f.severity, "resource_kind": f.resource_kind, "namespace": f.namespace,
            "resource_name": f.resource_name, "container": f.container, "explanation": f.explanation,
            "remediation": f.remediation, "evidence": f.evidence, "status": f.status,
            "first_seen": iso(f.first_seen), "last_seen": iso(f.last_seen), "resolved_at": iso(f.resolved_at)}


def scan(s: ImageScan, *, detail: bool = False) -> dict[str, Any]:
    out = {"id": s.id, "image": s.image, "digest": s.digest, "status": s.status, "trigger": s.trigger,
           "requested_by": s.requested_by, "started_at": iso(s.started_at), "finished_at": iso(s.finished_at),
           "error": s.error, "os_family": s.os_family, "counts": s.counts, "secret_count": s.secret_count,
           "misconfig_count": s.misconfig_count, "sbom_components": s.sbom_components,
           "scanner_version": s.scanner_version, "workloads": s.workloads}
    if detail:
        out["findings"] = [{"kind": f.kind, "rule_id": f.rule_id, "severity": f.severity, "title": f.title,
                            "target": f.target, "details": f.details} for f in s.findings]
    return out


def violation(v: PolicyViolation) -> dict[str, Any]:
    return {"id": v.id, "source": v.source, "policy": v.policy, "control": v.control, "mode": v.mode,
            "severity": v.severity, "result": v.result, "namespace": v.namespace,
            "resource_kind": v.resource_kind, "resource_name": v.resource_name, "message": v.message,
            "remediation": v.remediation, "status": v.status, "first_seen": iso(v.first_seen),
            "last_seen": iso(v.last_seen)}


def flow(f: NetworkFlow) -> dict[str, Any]:
    return {"id": f.id, "timestamp": iso(f.timestamp), "verdict": f.verdict, "drop_reason": f.drop_reason,
            "direction": f.direction, "protocol": f.protocol, "src_namespace": f.src_namespace,
            "src_pod": f.src_pod, "src_ip": f.src_ip, "dst_namespace": f.dst_namespace, "dst_pod": f.dst_pod,
            "dst_ip": f.dst_ip, "dst_port": f.dst_port, "dst_service": f.dst_service, "node": f.node}


def simulation(r: SimulationRun) -> dict[str, Any]:
    return {"id": r.id, "scenario_id": r.scenario_id, "status": r.status, "outcome": r.outcome,
            "requested_by": r.requested_by, "started_at": iso(r.started_at), "finished_at": iso(r.finished_at),
            "steps": r.steps, "checks": r.checks, "evidence": r.evidence, "error": r.error,
            "incident_id": r.incident_id}
