"""Cluster discovery: inventory snapshot, integration health and posture findings."""

from __future__ import annotations

import logging
from typing import Any

from kubernetes.client import ApiException
from sqlalchemy import select
from sqlalchemy.orm import Session

from kubeshield import audit
from kubeshield.config import get_settings
from kubeshield.k8s import posture
from kubeshield.k8s.client import kube, sanitize
from kubeshield.models import InventorySnapshot, PostureFinding, utcnow

log = logging.getLogger(__name__)

PLATFORM_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease", "local-path-storage", "cilium-secrets",
                       "falco", "kyverno"}

# (key, display name, namespace, kind, name)
INTEGRATIONS = (
    ("falco", "Falco runtime detection", "falco", "DaemonSet", "falco"),
    ("falcosidekick", "Falcosidekick forwarder", "falco", "Deployment", "falco-falcosidekick"),
    ("kyverno", "Kyverno admission controller", "kyverno", "Deployment", "kyverno-admission-controller"),
    ("kyverno-reports", "Kyverno reports controller", "kyverno", "Deployment", "kyverno-reports-controller"),
    ("cilium", "Cilium CNI agent", "kube-system", "DaemonSet", "cilium"),
    ("hubble-relay", "Hubble Relay", "kube-system", "Deployment", "hubble-relay"),
    ("tetragon", "Tetragon eBPF agent", "kube-system", "DaemonSet", "tetragon"),
)


def _workload_ready(kind: str, ns: str, name: str) -> dict[str, Any]:
    try:
        if kind == "DaemonSet":
            o = kube.apps.read_namespaced_daemon_set(name, ns, _request_timeout=10)
            desired, ready = o.status.desired_number_scheduled or 0, o.status.number_ready or 0
        else:
            o = kube.apps.read_namespaced_deployment(name, ns, _request_timeout=10)
            desired, ready = o.spec.replicas or 0, o.status.ready_replicas or 0
        images = [c.image for c in o.spec.template.spec.containers]
        state = "healthy" if desired and ready == desired else "degraded"
        return {"installed": True, "state": state, "desired": desired, "ready": ready, "images": images}
    except ApiException as exc:
        if exc.status == 404:
            return {"installed": False, "state": "not_installed"}
        return {"installed": None, "state": "unknown", "error": f"HTTP {exc.status}"}


def integrations() -> list[dict[str, Any]]:
    out = []
    for key, title, ns, kind, name in INTEGRATIONS:
        out.append({"key": key, "title": title, "namespace": ns, "kind": kind, "name": name,
                    **_workload_ready(kind, ns, name)})
    return out


def collect(db: Session) -> InventorySnapshot:
    """Take an inventory snapshot and refresh posture findings. Raises on API failure."""
    settings = get_settings()
    core, apps, rbac, net = kube.core, kube.apps, kube.rbac, kube.networking
    version = kube.version.get_code()

    nodes = []
    for n in core.list_node().items:
        cond = {c.type: c.status for c in (n.status.conditions or [])}
        info = n.status.node_info
        nodes.append({
            "name": n.metadata.name, "ready": cond.get("Ready") == "True",
            "kubelet": info.kubelet_version, "os": info.os_image, "kernel": info.kernel_version,
            "runtime": info.container_runtime_version, "arch": info.architecture,
            "cpu": n.status.capacity.get("cpu"), "memory": n.status.capacity.get("memory"),
            "roles": sorted(k.split("/", 1)[1] for k in (n.metadata.labels or {})
                            if k.startswith("node-role.kubernetes.io/")),
        })

    ns_items = core.list_namespace().items
    pods = core.list_pod_for_all_namespaces().items
    deployments = apps.list_deployment_for_all_namespaces().items
    daemonsets = apps.list_daemon_set_for_all_namespaces().items
    statefulsets = apps.list_stateful_set_for_all_namespaces().items
    service_accounts = core.list_service_account_for_all_namespaces().items
    netpols = net.list_network_policy_for_all_namespaces().items
    try:
        cnps = kube.custom.list_cluster_custom_object("cilium.io", "v2", "ciliumnetworkpolicies")["items"]
    except Exception:  # noqa: BLE001 - Cilium is optional
        cnps = []

    pods_by_ns: dict[str, int] = {}
    pod_rows = []
    for p in pods:
        ns = p.metadata.namespace
        pods_by_ns[ns] = pods_by_ns.get(ns, 0) + 1
        statuses = p.status.container_statuses or []
        pod_rows.append({
            "namespace": ns, "name": p.metadata.name, "phase": p.status.phase, "node": p.spec.node_name,
            "ip": p.status.pod_ip, "service_account": p.spec.service_account_name,
            "images": [c.image for c in p.spec.containers],
            "restarts": sum(s.restart_count for s in statuses),
            "ready": bool(statuses) and all(s.ready for s in statuses),
            "owner": (lambda r: f"{r[0].kind}/{r[0].name}" if r else None)(p.metadata.owner_references),
            "quarantined": (p.metadata.labels or {}).get("kubeshield.io/quarantine"),
            "privileged": any((c.security_context and c.security_context.privileged) for c in p.spec.containers),
            "host_network": bool(p.spec.host_network), "host_pid": bool(p.spec.host_pid),
            "created": p.metadata.creation_timestamp.isoformat() if p.metadata.creation_timestamp else None,
            "platform": ns in PLATFORM_NAMESPACES,
        })

    namespaces = []
    for n in ns_items:
        labels = n.metadata.labels or {}
        namespaces.append({
            "name": n.metadata.name,
            "lab": labels.get(settings.lab_label) == "true",
            "policy_mode": labels.get("kubeshield.io/policy-mode"),
            "platform": n.metadata.name in PLATFORM_NAMESPACES,
            "pods": pods_by_ns.get(n.metadata.name, 0),
            "network_policies": sum(1 for np in netpols if np.metadata.namespace == n.metadata.name),
            "cilium_policies": sum(1 for c in cnps if c["metadata"]["namespace"] == n.metadata.name),
            "phase": n.status.phase,
        })

    # ------------------------------------------------------------------ posture
    findings: list[posture.Finding] = []
    for kind, items in (("Deployment", deployments), ("DaemonSet", daemonsets), ("StatefulSet", statefulsets)):
        for o in items:
            if o.metadata.namespace in PLATFORM_NAMESPACES:
                continue
            findings += posture.check_workload(kind, sanitize(o))
    for p in pods:
        if p.metadata.namespace in PLATFORM_NAMESPACES or p.metadata.owner_references:
            continue  # controller-owned pods are covered by their controller
        findings += posture.check_workload("Pod", sanitize(p))

    roles = [("ClusterRole", None, sanitize(r)) for r in rbac.list_cluster_role().items]
    roles += [("Role", r.metadata.namespace, sanitize(r)) for r in rbac.list_role_for_all_namespaces().items]
    bindings = [("ClusterRoleBinding", None, sanitize(b)) for b in rbac.list_cluster_role_binding().items]
    bindings += [("RoleBinding", b.metadata.namespace, sanitize(b))
                 for b in rbac.list_role_binding_for_all_namespaces().items]
    findings += posture.check_rbac(roles, bindings)
    findings += posture.check_network_isolation(
        [sanitize(n) for n in ns_items if n.metadata.name not in PLATFORM_NAMESPACES],
        [sanitize(n) for n in netpols], cnps)

    _persist_findings(db, findings)

    data = {
        "kubernetes_version": version.git_version,
        "platform": version.platform,
        "nodes": nodes,
        "namespaces": namespaces,
        "pods": pod_rows,
        "counts": {
            "nodes": len(nodes), "namespaces": len(namespaces), "pods": len(pods),
            "deployments": len(deployments), "daemonsets": len(daemonsets), "statefulsets": len(statefulsets),
            "service_accounts": len(service_accounts), "network_policies": len(netpols),
            "cilium_network_policies": len(cnps),
            "privileged_pods": sum(1 for p in pod_rows if p["privileged"] and not p["platform"]),
            "lab_namespaces": sum(1 for n in namespaces if n["lab"]),
        },
        "integrations": integrations(),
    }
    snap = InventorySnapshot(ok=True, data=data)
    db.add(snap)
    db.flush()
    return snap


def _persist_findings(db: Session, findings: list[posture.Finding]) -> None:
    now = utcnow()
    seen: set[str] = set()
    for f in findings:
        fid = f.fingerprint
        if fid in seen:
            continue
        seen.add(fid)
        row = db.get(PostureFinding, fid)
        if row is None:
            db.add(PostureFinding(
                id=fid, check_id=f.check_id, title=f.title, category=f.category, severity=f.severity,
                resource_kind=f.resource_kind, namespace=f.namespace, resource_name=f.resource_name,
                container=f.container, explanation=f.explanation, remediation=f.remediation,
                evidence=f.evidence, status="open", first_seen=now, last_seen=now,
            ))
        else:
            row.last_seen, row.evidence, row.severity, row.title = now, f.evidence, f.severity, f.title
            if row.status == "resolved":
                row.status, row.resolved_at = "open", None
    for row in db.scalars(select(PostureFinding).where(PostureFinding.status == "open")):
        if row.id not in seen:
            row.status, row.resolved_at = "resolved", now
            audit.record(db, "system", "posture.resolved", f"{row.resource_kind}/{row.namespace}/"
                         f"{row.resource_name}", details={"check": row.check_id, "title": row.title})
    db.flush()


def record_failure(db: Session, error: str) -> None:
    db.add(InventorySnapshot(ok=False, error=error[:2000], data={}))
    db.flush()
