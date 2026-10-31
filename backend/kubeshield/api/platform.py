"""Overview, cluster, images, policies, network, simulation, ATT&CK and settings APIs."""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Annotated, Any

import yaml
from fastapi import APIRouter, Depends, HTTPException, Query
from kubernetes.client import ApiException
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from kubeshield import __version__, audit, mitre, settings_store
from kubeshield.api import serializers as ser
from kubeshield.api.core import Admin, Responder, Viewer
from kubeshield.catalog import DETECTIONS
from kubeshield.config import get_settings
from kubeshield.db import get_db
from kubeshield.k8s.client import KubeUnavailable, kube
from kubeshield.models import (
    ImageScan,
    Incident,
    InventorySnapshot,
    NetworkFlow,
    PolicyViolation,
    PostureFinding,
    ResponseAction,
    SecurityEvent,
    SimulationRun,
    Vulnerability,
    utcnow,
)
from kubeshield.network import hubble
from kubeshield.policy import kyverno
from kubeshield.scanners import trivy
from kubeshield.simulation import scenarios
from kubeshield.workers import worker_status

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1")
DB = Annotated[Session, Depends(get_db)]
SEV_ORDER = ("critical", "high", "medium", "low", "info")


def _latest_snapshot(db: Session) -> InventorySnapshot | None:
    return db.scalar(select(InventorySnapshot).where(InventorySnapshot.ok.is_(True))
                     .order_by(InventorySnapshot.taken_at.desc()).limit(1))


def _count_by(db: Session, column, *where) -> dict[str, int]:
    stmt = select(column, func.count()).group_by(column)
    for w in where:
        stmt = stmt.where(w)
    return {k: v for k, v in db.execute(stmt)}


# --------------------------------------------------------------------------- overview
@router.get("/overview")
def overview(db: DB, _: Viewer) -> dict[str, Any]:
    now = utcnow()
    day = now - timedelta(hours=24)
    snap = _latest_snapshot(db)
    open_inc = _count_by(db, Incident.severity, Incident.status.in_(("open", "investigating", "contained")))
    events_24h = _count_by(db, SecurityEvent.severity, SecurityEvent.timestamp >= day)

    # Hourly detection activity for the last 24h, split by severity.
    buckets: dict[str, dict[str, int]] = {}
    for i in range(24):
        h = (now - timedelta(hours=23 - i)).replace(minute=0, second=0, microsecond=0)
        buckets[h.isoformat()] = {s: 0 for s in SEV_ORDER}
    for ts, sev in db.execute(select(SecurityEvent.timestamp, SecurityEvent.severity)
                              .where(SecurityEvent.timestamp >= day)):
        key = ts.replace(minute=0, second=0, microsecond=0).isoformat()
        if key in buckets:
            buckets[key][sev] = buckets[key].get(sev, 0) + 1

    latest_scans = _latest_scans(db)
    vulnerable_images = sum(1 for s in latest_scans if (s.counts or {}).get("critical", 0)
                            + (s.counts or {}).get("high", 0) > 0)
    top_rules = db.execute(select(SecurityEvent.rule, func.count().label("n"))
                           .where(SecurityEvent.timestamp >= day).group_by(SecurityEvent.rule)
                           .order_by(func.count().desc()).limit(6)).all()
    recent = db.scalars(select(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(8)).all()
    return {
        "generated_at": now.isoformat(),
        "cluster": {
            "available": snap is not None,
            "snapshot_at": ser.iso(snap.taken_at) if snap else None,
            "kubernetes_version": snap.data.get("kubernetes_version") if snap else None,
            "counts": snap.data.get("counts", {}) if snap else {},
            "nodes_ready": sum(1 for n in snap.data.get("nodes", []) if n["ready"]) if snap else 0,
            "integrations": snap.data.get("integrations", []) if snap else [],
        },
        "incidents": {"open_by_severity": open_inc, "open_total": sum(open_inc.values())},
        "events_24h": {"by_severity": events_24h, "total": sum(events_24h.values()),
                       "by_source": _count_by(db, SecurityEvent.source, SecurityEvent.timestamp >= day)},
        "activity": [{"hour": k, **v} for k, v in buckets.items()],
        "top_rules": [{"rule": r, "count": n} for r, n in top_rules],
        "posture": {"open_by_severity": _count_by(db, PostureFinding.severity, PostureFinding.status == "open")},
        "policy": {
            "open_violations": db.scalar(select(func.count()).select_from(PolicyViolation)
                                         .where(PolicyViolation.status == "open")) or 0,
            "blocked_admissions": db.scalar(select(func.count()).select_from(PolicyViolation)
                                            .where(PolicyViolation.source == "admission")) or 0,
        },
        "images": {"scanned": len(latest_scans), "vulnerable": vulnerable_images,
                   "critical": sum((s.counts or {}).get("critical", 0) for s in latest_scans)},
        "responses": _count_by(db, ResponseAction.status),
        "recent_events": [ser.event(e) for e in recent],
    }


# --------------------------------------------------------------------------- system
@router.get("/system/status")
def system_status(db: DB, _: Viewer) -> dict[str, Any]:
    ok, err = kube.available()
    snap = _latest_snapshot(db)
    t_ok, t_version = trivy.available()
    last_falco = db.scalar(select(func.max(SecurityEvent.ingested_at)).where(SecurityEvent.source == "falco"))
    return {
        "version": __version__,
        "kubernetes": {"reachable": ok, "error": err, "mode": get_settings().kube_mode},
        "integrations": snap.data.get("integrations", []) if snap else [],
        "falco": {"last_event_ingested_at": ser.iso(last_falco)},
        "hubble": hubble.status.as_dict(),
        "trivy": {"available": t_ok, "version": t_version},
        "workers": worker_status(),
    }


@router.get("/detections")
def detections(db: DB, _: Viewer) -> list[dict[str, Any]]:
    validated = mitre.validated_detections(db)
    counts = _count_by(db, SecurityEvent.rule_id)
    return [{"id": d.id, "name": d.name, "source": d.source, "source_rule": d.source_rule,
             "severity": d.severity, "description": d.description, "techniques": list(d.techniques),
             "recommended_response": d.recommended_response, "scenario": d.scenario,
             "validated": validated.get(d.id), "event_count": counts.get(d.id, 0)} for d in DETECTIONS]


# --------------------------------------------------------------------------- cluster
@router.get("/cluster")
def cluster(db: DB, _: Viewer) -> dict[str, Any]:
    snap = _latest_snapshot(db)
    last_failure = db.scalar(select(InventorySnapshot).where(InventorySnapshot.ok.is_(False))
                             .order_by(InventorySnapshot.taken_at.desc()).limit(1))
    if snap is None:
        return {"available": False, "error": last_failure.error if last_failure else "no inventory yet"}
    return {"available": True, "snapshot_at": ser.iso(snap.taken_at), **snap.data,
            "last_error": last_failure.error if last_failure and last_failure.taken_at > snap.taken_at else None}


@router.post("/cluster/refresh", status_code=202)
def refresh_cluster(db: DB, p: Responder) -> dict[str, Any]:
    from kubeshield.k8s import inventory

    try:
        snap = inventory.collect(db)
    except (ApiException, KubeUnavailable) as exc:
        raise HTTPException(503, f"cluster unavailable: {exc}") from exc
    audit.record(db, p.username, "cluster.refreshed")
    return {"snapshot_at": ser.iso(snap.taken_at)}


@router.get("/posture/findings")
def posture_findings(
    db: DB, _: Viewer,
    status_: Annotated[str, Query(alias="status")] = "open",
    severity: Annotated[list[str] | None, Query()] = None,
    category: str | None = None,
    namespace: str | None = None,
    q: Annotated[str | None, Query(max_length=200)] = None,
) -> dict[str, Any]:
    stmt = select(PostureFinding).where(PostureFinding.status == status_)
    if severity:
        stmt = stmt.where(PostureFinding.severity.in_(severity))
    if category:
        stmt = stmt.where(PostureFinding.category == category)
    if namespace:
        stmt = stmt.where(PostureFinding.namespace == namespace)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(PostureFinding.title.ilike(like), PostureFinding.resource_name.ilike(like)))
    rows = db.scalars(stmt.order_by(PostureFinding.last_seen.desc())).all()
    rows = sorted(rows, key=lambda f: SEV_ORDER.index(f.severity) if f.severity in SEV_ORDER else 9)
    return {"total": len(rows), "items": [ser.finding(f) for f in rows],
            "by_category": _count_by(db, PostureFinding.category, PostureFinding.status == status_)}


# --------------------------------------------------------------------------- images
def _latest_scans(db: Session) -> list[ImageScan]:
    sub = (select(ImageScan.image, func.max(ImageScan.started_at).label("m"))
           .where(ImageScan.status == "succeeded").group_by(ImageScan.image).subquery())
    return list(db.scalars(select(ImageScan).join(sub, (ImageScan.image == sub.c.image)
                                                  & (ImageScan.started_at == sub.c.m))))


@router.get("/images")
def images(db: DB, _: Viewer) -> dict[str, Any]:
    latest = sorted(_latest_scans(db), key=lambda s: (-(s.counts or {}).get("critical", 0),
                                                       -(s.counts or {}).get("high", 0)))
    recent = db.scalars(select(ImageScan).order_by(ImageScan.started_at.desc()).limit(30)).all()
    t_ok, t_version = trivy.available()
    return {"scanner": {"available": t_ok, "version": t_version},
            "images": [ser.scan(s) for s in latest], "recent_scans": [ser.scan(s) for s in recent]}


@router.get("/images/scans/{scan_id}")
def image_scan(scan_id: str, db: DB, _: Viewer) -> dict[str, Any]:
    s = db.get(ImageScan, scan_id)
    if s is None:
        raise HTTPException(404, "scan not found")
    return ser.scan(s, detail=True)


@router.get("/images/scans/{scan_id}/vulnerabilities")
def scan_vulnerabilities(
    scan_id: str, db: DB, _: Viewer,
    severity: Annotated[list[str] | None, Query()] = None,
    fixable: bool | None = None,
    q: Annotated[str | None, Query(max_length=200)] = None,
    limit: Annotated[int, Query(ge=1, le=2000)] = 500,
) -> dict[str, Any]:
    stmt = select(Vulnerability).where(Vulnerability.scan_id == scan_id)
    if severity:
        stmt = stmt.where(Vulnerability.severity.in_(severity))
    if fixable is True:
        stmt = stmt.where(Vulnerability.fixed_version.is_not(None))
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(Vulnerability.vuln_id.ilike(like), Vulnerability.pkg_name.ilike(like)))
    rows = db.scalars(stmt).all()
    rows = sorted(rows, key=lambda v: (SEV_ORDER.index(v.severity) if v.severity in SEV_ORDER else 9,
                                       -(v.cvss_score or 0)))[:limit]
    return {"total": len(rows), "items": [{
        "vuln_id": v.vuln_id, "pkg_name": v.pkg_name, "pkg_type": v.pkg_type,
        "installed_version": v.installed_version, "fixed_version": v.fixed_version, "severity": v.severity,
        "cvss_score": v.cvss_score, "title": v.title, "primary_url": v.primary_url, "target": v.target,
        "remediation": (f"Upgrade {v.pkg_name} to {v.fixed_version} or rebuild on a patched base image."
                        if v.fixed_version else "No fixed version published; consider a different base image "
                        "or compensating controls."),
    } for v in rows]}


@router.get("/images/scans/{scan_id}/sbom")
def scan_sbom(scan_id: str, db: DB, _: Viewer) -> dict[str, Any]:
    s = db.get(ImageScan, scan_id)
    if s is None or s.sbom is None:
        raise HTTPException(404, "SBOM not available for this scan")
    return s.sbom


class ScanIn(BaseModel):
    image: str = Field(min_length=3, max_length=512)


@router.post("/images/scans", status_code=202)
def request_scan(body: ScanIn, db: DB, p: Responder) -> dict[str, Any]:
    try:
        scan = trivy.queue_scan(db, body.image, "manual", p.username)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    audit.record(db, p.username, "image.scan_requested", body.image, details={"scan_id": scan.id})
    return ser.scan(scan)


class PreflightIn(BaseModel):
    manifest: str = Field(min_length=10, max_length=256_000)
    scan_images: bool = True


ALLOWED_PREFLIGHT_KINDS = {"Pod", "Deployment", "DaemonSet", "StatefulSet", "Job", "CronJob", "ReplicaSet"}


def _dry_run(kind: str, ns: str, body: dict[str, Any]) -> None:
    fn = {
        "Pod": lambda: kube.core.create_namespaced_pod(ns, body, dry_run="All"),
        "Deployment": lambda: kube.apps.create_namespaced_deployment(ns, body, dry_run="All"),
        "DaemonSet": lambda: kube.apps.create_namespaced_daemon_set(ns, body, dry_run="All"),
        "StatefulSet": lambda: kube.apps.create_namespaced_stateful_set(ns, body, dry_run="All"),
        "ReplicaSet": lambda: kube.apps.create_namespaced_replica_set(ns, body, dry_run="All"),
    }.get(kind)
    if fn is None:
        from kubernetes import client as k8s

        batch = k8s.BatchV1Api(kube.api())
        fn = (lambda: batch.create_namespaced_job(ns, body, dry_run="All")) if kind == "Job" else (
            lambda: batch.create_namespaced_cron_job(ns, body, dry_run="All"))
    fn()


def _images_in(doc: dict[str, Any]) -> list[str]:
    spec = doc.get("spec", {})
    if doc["kind"] == "CronJob":
        spec = spec.get("jobTemplate", {}).get("spec", {})
    pod = spec if doc["kind"] == "Pod" else spec.get("template", {}).get("spec", {})
    return [c.get("image", "") for k in ("initContainers", "containers") for c in pod.get(k) or []]


@router.post("/preflight")
def preflight(body: PreflightIn, db: DB, p: Responder) -> dict[str, Any]:
    """Pre-deployment gate: Kyverno admission (server-side dry run), Trivy config and image scans."""
    try:
        docs = [d for d in yaml.safe_load_all(body.manifest) if d]
    except yaml.YAMLError as exc:
        raise HTTPException(422, f"invalid YAML: {exc}") from exc
    if not docs or len(docs) > 20 or not all(isinstance(d, dict) for d in docs):
        raise HTTPException(422, "manifest must contain 1-20 Kubernetes objects")
    ns = get_settings().preflight_namespace
    resources, images = [], set()
    for d in docs:
        kind, name = d.get("kind"), (d.get("metadata") or {}).get("name", "unnamed")
        if kind not in ALLOWED_PREFLIGHT_KINDS:
            resources.append({"kind": kind, "name": name, "admission": "skipped",
                              "message": "kind not evaluated by the pre-deployment gate"})
            continue
        d.setdefault("metadata", {})["namespace"] = ns
        images.update(i for i in _images_in(d) if i)
        try:
            _dry_run(kind, ns, d)
            resources.append({"kind": kind, "name": name, "admission": "allowed", "message": None})
        except ApiException as exc:
            import json as _json

            try:
                msg = _json.loads(exc.body).get("message", exc.reason)
            except (ValueError, TypeError, AttributeError):
                msg = exc.reason
            resources.append({"kind": kind, "name": name, "admission": "denied" if exc.status in (400, 403)
                              else "error", "message": msg})
        except KubeUnavailable as exc:
            resources.append({"kind": kind, "name": name, "admission": "error", "message": str(exc)})
    try:
        config_scan = trivy.scan_manifest(body.manifest)
    except trivy.TrivyError as exc:
        config_scan = {"error": str(exc), "findings": []}

    image_results = []
    for image in sorted(images):
        entry: dict[str, Any] = {"image": image}
        try:
            trivy.validate_image(image)
        except ValueError:
            entry.update(status="invalid")
            image_results.append(entry)
            continue
        latest = db.scalar(select(ImageScan).where(ImageScan.image == image, ImageScan.status == "succeeded")
                           .order_by(ImageScan.started_at.desc()).limit(1))
        if latest:
            entry.update(status="scanned", scan_id=latest.id, counts=latest.counts,
                         scanned_at=ser.iso(latest.finished_at))
        elif body.scan_images:
            scan = trivy.queue_scan(db, image, "preflight", p.username)
            entry.update(status=scan.status, scan_id=scan.id)
        else:
            entry.update(status="not_scanned")
        image_results.append(entry)

    denied = any(r["admission"] == "denied" for r in resources)
    critical_images = any((i.get("counts") or {}).get("critical", 0) > 0 for i in image_results)
    high_config = any(f["severity"] in ("critical", "high") for f in config_scan.get("findings", []))
    pending = any(i["status"] in ("queued", "running") for i in image_results)
    verdict = "fail" if denied or critical_images else ("warn" if high_config or pending else "pass")
    audit.record(db, p.username, "preflight.evaluated", ",".join(f"{r['kind']}/{r['name']}" for r in resources),
                 details={"verdict": verdict})
    return {"verdict": verdict, "namespace": ns, "resources": resources, "config_findings": config_scan,
            "images": image_results}


# --------------------------------------------------------------------------- policies
@router.get("/policies")
def policies(db: DB, _: Viewer) -> dict[str, Any]:
    try:
        items = kyverno.list_policies()
        error = None
    except (ApiException, KubeUnavailable) as exc:
        items, error = [], str(exc)
    open_by_policy = _count_by(db, PolicyViolation.policy, PolicyViolation.status == "open")
    denied_by_policy = _count_by(db, PolicyViolation.policy, PolicyViolation.source == "admission")
    for p in items:
        p["open_violations"] = open_by_policy.get(p["name"], 0)
        p["admission_denials"] = denied_by_policy.get(p["name"], 0)
    return {"available": error is None, "error": error, "policies": items}


@router.get("/policies/violations")
def policy_violations(
    db: DB, _: Viewer,
    source: str | None = None,
    status_: Annotated[str | None, Query(alias="status")] = None,
    namespace: str | None = None,
    severity: Annotated[list[str] | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 500,
) -> dict[str, Any]:
    stmt = select(PolicyViolation)
    if source:
        stmt = stmt.where(PolicyViolation.source == source)
    if status_:
        stmt = stmt.where(PolicyViolation.status == status_)
    if namespace:
        stmt = stmt.where(PolicyViolation.namespace == namespace)
    if severity:
        stmt = stmt.where(PolicyViolation.severity.in_(severity))
    rows = db.scalars(stmt.order_by(PolicyViolation.last_seen.desc()).limit(limit)).all()
    return {"total": len(rows), "items": [ser.violation(v) for v in rows]}


# --------------------------------------------------------------------------- network
@router.get("/network/flows")
def network_flows(
    db: DB, _: Viewer,
    verdict: str | None = None,
    namespace: str | None = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
) -> dict[str, Any]:
    stmt = select(NetworkFlow)
    if verdict:
        stmt = stmt.where(NetworkFlow.verdict == verdict)
    if namespace:
        stmt = stmt.where(or_(NetworkFlow.src_namespace == namespace, NetworkFlow.dst_namespace == namespace))
    rows = db.scalars(stmt.order_by(NetworkFlow.timestamp.desc()).limit(limit)).all()
    return {"source": "cilium-hubble", "hubble": hubble.status.as_dict(), "items": [ser.flow(f) for f in rows]}


@router.get("/network/summary")
def network_summary(db: DB, _: Viewer) -> dict[str, Any]:
    since = utcnow() - timedelta(hours=24)
    edges = db.execute(
        select(NetworkFlow.src_namespace, NetworkFlow.dst_namespace, NetworkFlow.verdict, func.count())
        .where(NetworkFlow.timestamp >= since)
        .group_by(NetworkFlow.src_namespace, NetworkFlow.dst_namespace, NetworkFlow.verdict)).all()
    snap = _latest_snapshot(db)
    namespaces = snap.data.get("namespaces", []) if snap else []
    try:
        k8s_policies = [{"namespace": n.metadata.namespace, "name": n.metadata.name,
                         "pod_selector": n.spec.pod_selector.match_labels or {},
                         "policy_types": n.spec.policy_types or [],
                         "ingress_rules": len(n.spec.ingress or []), "egress_rules": len(n.spec.egress or [])}
                        for n in kube.networking.list_network_policy_for_all_namespaces().items]
        cilium_policies = [{"namespace": c["metadata"]["namespace"], "name": c["metadata"]["name"],
                            "deny": bool(c["spec"].get("ingressDeny") or c["spec"].get("egressDeny")),
                            "description": c["spec"].get("description"),
                            "managed_by_kubeshield": (c["metadata"].get("labels") or {}).get(
                                "app.kubernetes.io/managed-by") == "kubeshield"}
                           for c in kube.custom.list_cluster_custom_object("cilium.io", "v2",
                                                                           "ciliumnetworkpolicies")["items"]]
        error = None
    except (ApiException, KubeUnavailable) as exc:
        k8s_policies, cilium_policies, error = [], [], str(exc)
    return {
        "window_hours": 24,
        "observation_source": "Cilium Hubble Relay (eBPF datapath flow events)",
        "hubble": hubble.status.as_dict(),
        "edges": [{"src": s or "external", "dst": d or "external", "verdict": v, "count": c}
                  for s, d, v, c in edges],
        "verdicts": _count_by(db, NetworkFlow.verdict, NetworkFlow.timestamp >= since),
        "namespaces": [{"name": n["name"], "lab": n["lab"], "network_policies": n["network_policies"],
                        "cilium_policies": n.get("cilium_policies", 0), "platform": n["platform"]}
                       for n in namespaces],
        "network_policies": k8s_policies,
        "cilium_policies": cilium_policies,
        "error": error,
    }


# --------------------------------------------------------------------------- simulations
@router.get("/simulations/scenarios")
def list_scenarios(db: DB, _: Viewer) -> list[dict[str, Any]]:
    out = []
    for s in scenarios.SCENARIOS.values():
        last = db.scalar(select(SimulationRun).where(SimulationRun.scenario_id == s.id)
                         .order_by(SimulationRun.started_at.desc()).limit(1))
        out.append({
            "id": s.id, "title": s.title, "description": s.description, "objective": s.objective,
            "target": s.target, "procedure": list(s.procedure), "expected_telemetry": s.expected_telemetry,
            "expected_detections": list(s.expected_detections), "expected_response": s.expected_response,
            "techniques": list(s.techniques), "kind": s.kind,
            "last_run": ser.simulation(last) if last else None,
        })
    return out


@router.get("/simulations/runs")
def list_runs(db: DB, _: Viewer, limit: Annotated[int, Query(ge=1, le=200)] = 50) -> list[dict[str, Any]]:
    return [ser.simulation(r) for r in db.scalars(select(SimulationRun).order_by(
        SimulationRun.started_at.desc()).limit(limit))]


@router.get("/simulations/runs/{run_id}")
def get_run(run_id: str, db: DB, _: Viewer) -> dict[str, Any]:
    r = db.get(SimulationRun, run_id)
    if r is None:
        raise HTTPException(404, "run not found")
    return ser.simulation(r)


class SimulationIn(BaseModel):
    scenario_id: str = Field(max_length=64)


@router.post("/simulations/runs", status_code=202)
def start_run(body: SimulationIn, db: DB, p: Responder) -> dict[str, Any]:
    if not settings_store.get(db, "simulation.enabled"):
        raise HTTPException(403, "attack simulation is disabled in settings")
    try:
        run = scenarios.start(db, body.scenario_id, p.username)
    except KeyError as exc:
        raise HTTPException(404, "unknown scenario") from exc
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from exc
    return ser.simulation(run)


# --------------------------------------------------------------------------- ATT&CK
@router.get("/mitre/coverage")
def mitre_coverage(db: DB, _: Viewer) -> dict[str, Any]:
    return mitre.coverage(db)


# --------------------------------------------------------------------------- settings
@router.get("/settings")
def get_app_settings(db: DB, _: Viewer) -> dict[str, Any]:
    s = get_settings()
    return {
        "runtime": settings_store.get_all(db),
        "static": {"lab_label": s.lab_label, "kube_mode": s.kube_mode, "preflight_namespace": s.preflight_namespace,
                   "hubble_relay_address": s.hubble_relay_address, "incident_window_minutes":
                       s.incident_window_minutes, "session_ttl_minutes": s.session_ttl_minutes},
    }


class SettingIn(BaseModel):
    key: str = Field(max_length=64)
    value: bool | str


@router.put("/settings")
def put_setting(body: SettingIn, db: DB, p: Admin) -> dict[str, Any]:
    if body.key == "incidents.min_severity" and body.value not in SEV_ORDER:
        raise HTTPException(422, "invalid severity")
    before = settings_store.get(db, body.key) if body.key in settings_store.DEFAULTS else None
    try:
        settings_store.set_value(db, body.key, body.value, p.username)
    except KeyError as exc:
        raise HTTPException(404, "unknown setting") from exc
    except TypeError as exc:
        raise HTTPException(422, str(exc)) from exc
    audit.record(db, p.username, "settings.changed", body.key, details={"from": before, "to": body.value})
    return settings_store.get_all(db)
