"""Kyverno integration: policy status, PolicyReport results and admission denials."""

from __future__ import annotations

import hashlib
import logging
import re
from typing import Any

from kubernetes.client import ApiException
from sqlalchemy import select
from sqlalchemy.orm import Session

from kubeshield import ingest
from kubeshield.k8s.client import kube
from kubeshield.models import PolicyViolation, utcnow

log = logging.getLogger(__name__)

VPOL = ("policies.kyverno.io", "v1", "validatingpolicies")
REPORTS = ("wgpolicyk8s.io", "v1alpha2", "policyreports")
CLUSTER_REPORTS = ("wgpolicyk8s.io", "v1alpha2", "clusterpolicyreports")
# "Pod lab-apps/web-x: fail (blocked); <message>"
DENIAL_RE = re.compile(r"^(?P<kind>\w+) (?P<ns>[^/\s]+)/(?P<name>\S+): fail \(blocked\); (?P<msg>.*)$", re.S)
EVENTS_NAMESPACE = "default"


def _fp(*parts: str | None) -> str:
    return hashlib.sha256("|".join(p or "" for p in parts).encode()).hexdigest()[:40]


def list_policies() -> list[dict[str, Any]]:
    items = kube.custom.list_cluster_custom_object(*VPOL)["items"]
    out = []
    for p in items:
        meta, spec, status = p["metadata"], p.get("spec", {}), p.get("status", {})
        ann, labels = meta.get("annotations") or {}, meta.get("labels") or {}
        cond = status.get("conditionStatus") or {}
        out.append({
            "name": meta["name"],
            "control": labels.get("kubeshield.io/control"),
            "title": ann.get("kubeshield.io/title", meta["name"]),
            "severity": ann.get("kubeshield.io/severity", "medium"),
            "remediation": ann.get("kubeshield.io/remediation", ""),
            "mode": "enforce" if "Deny" in (spec.get("validationActions") or []) else "audit",
            "validation_actions": spec.get("validationActions") or [],
            "namespace_selector": (spec.get("matchConstraints") or {}).get("namespaceSelector"),
            "background": ((spec.get("evaluation") or {}).get("background") or {}).get("enabled", True),
            "ready": cond.get("ready"),
            "message": cond.get("message"),
            "managed_by_kubeshield": labels.get("app.kubernetes.io/part-of") == "kubeshield",
            "rules": [v.get("message") for v in spec.get("validations") or []],
        })
    return sorted(out, key=lambda x: (x["control"] or x["name"], x["mode"]))


def _policy_meta(policies: dict[str, dict[str, Any]], name: str) -> dict[str, Any]:
    return policies.get(name, {"severity": "medium", "remediation": "", "control": None, "mode": None})


def sync(db: Session) -> dict[str, int]:
    """Refresh PolicyViolation rows from PolicyReports and Kyverno admission events."""
    policies = {p["name"]: p for p in list_policies()}
    now = utcnow()
    seen: set[str] = set()
    counts = {"report": 0, "admission": 0}

    reports = kube.custom.list_cluster_custom_object(*REPORTS)["items"]
    try:
        reports += kube.custom.list_cluster_custom_object(*CLUSTER_REPORTS)["items"]
    except ApiException:
        pass
    for rep in reports:
        scope = rep.get("scope") or {}
        for r in rep.get("results") or []:
            if r.get("result") not in ("fail", "warn"):
                continue
            pname = r.get("policy", "")
            meta = _policy_meta(policies, pname)
            res = (r.get("resources") or [scope])[0] if (r.get("resources") or scope) else {}
            ns = res.get("namespace") or rep["metadata"].get("namespace")
            fid = _fp("report", pname, r.get("rule"), ns, res.get("kind"), res.get("name"))
            seen.add(fid)
            row = db.get(PolicyViolation, fid)
            if row is None:
                db.add(PolicyViolation(
                    id=fid, source="report", policy=pname, control=meta.get("control"), mode=meta.get("mode"),
                    severity=meta.get("severity", "medium"), result=r["result"], namespace=ns,
                    resource_kind=res.get("kind"), resource_name=res.get("name"),
                    message=r.get("message") or "", remediation=meta.get("remediation", ""),
                    status="open", first_seen=now, last_seen=now))
                counts["report"] += 1
            else:
                row.last_seen, row.status, row.message = now, "open", r.get("message") or row.message
    for row in db.scalars(select(PolicyViolation).where(PolicyViolation.source == "report",
                                                        PolicyViolation.status == "open")):
        if row.id not in seen:
            row.status = "resolved"

    counts["admission"] = _sync_denials(db, policies)
    db.flush()
    return counts


def _sync_denials(db: Session, policies: dict[str, dict[str, Any]]) -> int:
    created = 0
    events = kube.core.list_namespaced_event(EVENTS_NAMESPACE, field_selector="reason=PolicyViolation").items
    for ev in events:
        if (ev.reporting_component or "") != "kyverno-admission":
            continue
        m = DENIAL_RE.match(ev.message or "")
        if not m:
            continue
        pname = ev.involved_object.name
        meta = _policy_meta(policies, pname)
        ts = ev.last_timestamp or ev.event_time or ev.metadata.creation_timestamp or utcnow()
        fid = _fp("admission", ev.metadata.uid)
        if db.get(PolicyViolation, fid) is not None:
            continue
        db.add(PolicyViolation(
            id=fid, source="admission", policy=pname, control=meta.get("control"), mode="enforce",
            severity=meta.get("severity", "medium"), result="denied", namespace=m["ns"],
            resource_kind=m["kind"], resource_name=m["name"], message=m["msg"].strip(),
            remediation=meta.get("remediation", ""), status="blocked", first_seen=ts, last_seen=ts))
        created += 1
        if meta.get("control") in ("disallow-privileged", "disallow-host-pid-ipc", "disallow-host-path"):
            _admission_event(db, fid, pname, m, meta, ts)
    return created


def _admission_event(db: Session, fid: str, policy: str, m: re.Match[str], meta: dict[str, Any], ts) -> None:
    """Privileged / host-namespace deployment attempts are security events, not just hygiene."""
    from kubeshield.catalog import DETECTIONS_BY_ID

    det = DETECTIONS_BY_ID["ks.201"]
    ingest.store_event(db, {
        "id": f"kyverno_{fid}",
        "source": "kyverno",
        "rule": f"Admission denied by {policy}",
        "rule_id": det.id,
        "severity": "high",
        "source_priority": "blocked",
        "timestamp": ts,
        "namespace": m["ns"],
        "pod": m["name"],
        "container": None,
        "container_id": None,
        "image": None,
        "node": None,
        "process": {},
        "message": f"Kyverno blocked {m['kind']} {m['ns']}/{m['name']}: {m['msg'].strip()}",
        "evidence": {"policy": policy, "control": meta.get("control"), "decision": "denied"},
        "tags": ["kubeshield", det.id, "kyverno", "admission"],
        "techniques": list(det.techniques),
        "recommended_response": det.recommended_response,
        "raw": {"policy": policy, "message": m.group(0)},
    })
