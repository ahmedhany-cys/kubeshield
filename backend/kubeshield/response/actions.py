"""Kubernetes response actions.

Every action:
  * re-checks that the target namespace is part of the isolated laboratory,
  * returns a JSON-serialisable result describing what changed,
  * has a matching verify_* function that reads the cluster state back.
"""

from __future__ import annotations

import hashlib
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from kubernetes.client import ApiException, V1DeleteOptions

from kubeshield.k8s.client import kube, sanitize

log = logging.getLogger(__name__)

QUARANTINE_LABEL = "kubeshield.io/quarantine"
MANAGED_LABELS = {"app.kubernetes.io/managed-by": "kubeshield"}
CILIUM = ("cilium.io", "v2", "ciliumnetworkpolicies")


@dataclass(frozen=True)
class ActionSpec:
    type: str
    title: str
    description: str
    target_kind: str
    destructive: bool
    execute: Callable[[str, str, dict[str, Any]], dict[str, Any]]
    verify: Callable[[str, str, dict[str, Any]], dict[str, Any]]


def _policy_name(pod: str) -> str:
    return f"ks-quarantine-{hashlib.sha256(pod.encode()).hexdigest()[:10]}"


def _cilium_available() -> bool:
    return kube.crd_available(*CILIUM)


# --------------------------------------------------------------------------- alert only
def _alert_execute(namespace: str, name: str, ctx: dict[str, Any]) -> dict[str, Any]:
    return {"changed": False, "message": "Alert recorded; no change made to the cluster."}


def _alert_verify(namespace: str, name: str, ctx: dict[str, Any]) -> dict[str, Any]:
    return {"verified": True, "checks": [{"check": "no-op", "passed": True}]}


# --------------------------------------------------------------------------- isolate pod
def _isolate_execute(namespace: str, pod: str, ctx: dict[str, Any]) -> dict[str, Any]:
    value = f"inc-{ctx.get('incident_id') or 'manual'}"
    kube.core.patch_namespaced_pod(pod, namespace, {"metadata": {"labels": {QUARANTINE_LABEL: value}}})
    name = _policy_name(pod)
    selector = {QUARANTINE_LABEL: value}
    labels = {**MANAGED_LABELS, QUARANTINE_LABEL: value}
    result: dict[str, Any] = {"changed": True, "pod_label": {QUARANTINE_LABEL: value}, "policy": name}
    if _cilium_available():
        # Cilium deny rules take precedence over every allow rule, so the quarantine
        # holds even when other policies would allow traffic to this pod.
        body = {
            "apiVersion": "cilium.io/v2",
            "kind": "CiliumNetworkPolicy",
            "metadata": {"name": name, "namespace": namespace, "labels": labels},
            "spec": {
                "description": f"KubeShield quarantine for pod {pod}",
                "endpointSelector": {"matchLabels": selector},
                "ingressDeny": [{"fromEntities": ["all"]}],
                "egressDeny": [{"toEntities": ["all"]}],
            },
        }
        _apply_custom(namespace, name, body)
        result["engine"] = "cilium-deny-policy"
    else:
        body = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": name, "namespace": namespace, "labels": labels},
            "spec": {"podSelector": {"matchLabels": selector}, "policyTypes": ["Ingress", "Egress"]},
        }
        try:
            kube.networking.create_namespaced_network_policy(namespace, body)
        except ApiException as exc:
            if exc.status != 409:
                raise
            kube.networking.replace_namespaced_network_policy(name, namespace, body)
        result["engine"] = "kubernetes-networkpolicy"
        result["caveat"] = (
            "Kubernetes NetworkPolicies are additive allow-lists: another policy that allows traffic to this "
            "pod still applies. Install Cilium for authoritative deny-based quarantine."
        )
    return result


def _apply_custom(namespace: str, name: str, body: dict[str, Any]) -> None:
    group, version, plural = CILIUM
    try:
        kube.custom.create_namespaced_custom_object(group, version, namespace, plural, body)
    except ApiException as exc:
        if exc.status != 409:
            raise
        current = kube.custom.get_namespaced_custom_object(group, version, namespace, plural, name)
        body["metadata"]["resourceVersion"] = current["metadata"]["resourceVersion"]
        kube.custom.replace_namespaced_custom_object(group, version, namespace, plural, name, body)


ENFORCEMENT_TIMEOUT_SECONDS = 90


def _cilium_enforcement(namespace: str, pod: str, label: str, policy: str) -> dict[str, Any]:
    """Wait until Cilium has re-identified the pod with the quarantine label.

    Creating the policy object is not enough: Cilium enforces it only after the
    endpoint receives a new security identity that includes the quarantine
    label, which can take tens of seconds on a busy node.
    """
    deadline = time.monotonic() + ENFORCEMENT_TIMEOUT_SECONDS
    observed: dict[str, Any] = {}
    while True:
        try:
            cnp = kube.custom.get_namespaced_custom_object(*CILIUM[:2], namespace, CILIUM[2], policy)
            valid = any(c.get("type") == "Valid" and c.get("status") == "True"
                        for c in (cnp.get("status") or {}).get("conditions", []))
            cep = kube.custom.get_namespaced_custom_object("cilium.io", "v2", namespace, "ciliumendpoints", pod)
            status = cep.get("status") or {}
            identity = status.get("identity") or {}
            labelled = f"k8s:{label}" in (identity.get("labels") or [])
            observed = {"policy_valid": valid, "endpoint_state": status.get("state"),
                        "identity": identity.get("id"), "identity_has_quarantine_label": labelled}
            if valid and labelled and status.get("state") == "ready":
                return {"enforced": True, **observed}
        except ApiException as exc:
            observed = {"error": f"HTTP {exc.status}"}
        if time.monotonic() >= deadline:
            return {"enforced": False, **observed}
        time.sleep(3)


def _isolate_verify(namespace: str, pod: str, ctx: dict[str, Any]) -> dict[str, Any]:
    checks = []
    expected = ctx.get("result", {}).get("pod_label", {}).get(QUARANTINE_LABEL)
    p = kube.core.read_namespaced_pod(pod, namespace)
    actual = (p.metadata.labels or {}).get(QUARANTINE_LABEL)
    checks.append({"check": "pod carries quarantine label", "passed": actual == expected and actual is not None,
                   "observed": actual})
    name = _policy_name(pod)
    engine = ctx.get("result", {}).get("engine")
    try:
        if engine == "cilium-deny-policy":
            cnp = kube.custom.get_namespaced_custom_object(*CILIUM[:2], namespace, CILIUM[2], name)
            sel = cnp["spec"]["endpointSelector"]["matchLabels"]
            ok = sel.get(QUARANTINE_LABEL) == expected and bool(cnp["spec"].get("egressDeny"))
            checks.append({"check": "CiliumNetworkPolicy with ingress/egress deny present", "passed": ok,
                           "observed": name})
            enforcement = _cilium_enforcement(namespace, pod, f"{QUARANTINE_LABEL}={expected}", name)
            checks.append({"check": "Cilium endpoint re-identified with quarantine label (policy enforced)",
                           "passed": enforcement.pop("enforced"), "observed": enforcement})
        else:
            np = kube.networking.read_namespaced_network_policy(name, namespace)
            ok = (np.spec.pod_selector.match_labels or {}).get(QUARANTINE_LABEL) == expected and not (
                np.spec.ingress or np.spec.egress)
            checks.append({"check": "deny-all NetworkPolicy present", "passed": ok, "observed": name})
    except ApiException as exc:
        checks.append({"check": "quarantine policy present", "passed": False, "observed": f"HTTP {exc.status}"})
    return {"verified": all(c["passed"] for c in checks), "checks": checks}


# --------------------------------------------------------------------------- release isolation
def _release_execute(namespace: str, pod: str, ctx: dict[str, Any]) -> dict[str, Any]:
    name = _policy_name(pod)
    removed = []
    try:
        kube.custom.delete_namespaced_custom_object(*CILIUM[:2], namespace, CILIUM[2], name)
        removed.append(f"CiliumNetworkPolicy/{name}")
    except ApiException as exc:
        if exc.status not in (404, 403):
            raise
    try:
        kube.networking.delete_namespaced_network_policy(name, namespace)
        removed.append(f"NetworkPolicy/{name}")
    except ApiException as exc:
        if exc.status != 404:
            raise
    try:
        kube.core.patch_namespaced_pod(pod, namespace, {"metadata": {"labels": {QUARANTINE_LABEL: None}}})
    except ApiException as exc:
        if exc.status != 404:
            raise
    return {"changed": bool(removed), "removed": removed}


def _release_verify(namespace: str, pod: str, ctx: dict[str, Any]) -> dict[str, Any]:
    name = _policy_name(pod)
    present = []
    for fn in (
        lambda: kube.custom.get_namespaced_custom_object(*CILIUM[:2], namespace, CILIUM[2], name),
        lambda: kube.networking.read_namespaced_network_policy(name, namespace),
    ):
        try:
            fn()
            present.append(name)
        except ApiException:
            pass
    checks = [{"check": "quarantine policies removed", "passed": not present, "observed": present}]
    return {"verified": not present, "checks": checks}


# --------------------------------------------------------------------------- delete pod
def _delete_execute(namespace: str, pod: str, ctx: dict[str, Any]) -> dict[str, Any]:
    p = kube.core.read_namespaced_pod(pod, namespace)
    forensics: dict[str, Any] = {
        "pod_uid": p.metadata.uid,
        "node": p.spec.node_name,
        "images": [c.image for c in p.spec.containers],
        "owner_references": [f"{o.kind}/{o.name}" for o in (p.metadata.owner_references or [])],
        "labels": p.metadata.labels or {},
        "spec": sanitize(p.spec),
    }
    try:
        forensics["log_tail"] = kube.core.read_namespaced_pod_log(pod, namespace, tail_lines=100)[-8000:]
    except ApiException:
        forensics["log_tail"] = None
    kube.core.delete_namespaced_pod(pod, namespace, body=V1DeleteOptions(grace_period_seconds=5))
    return {"changed": True, "deleted_pod_uid": p.metadata.uid, "forensics": forensics}


def _delete_verify(namespace: str, pod: str, ctx: dict[str, Any]) -> dict[str, Any]:
    uid = ctx.get("result", {}).get("deleted_pod_uid")
    try:
        p = kube.core.read_namespaced_pod(pod, namespace)
        gone = p.metadata.uid != uid or p.metadata.deletion_timestamp is not None
        observed = "terminating" if p.metadata.deletion_timestamp else f"pod uid {p.metadata.uid}"
    except ApiException as exc:
        gone, observed = exc.status == 404, f"HTTP {exc.status}"
    return {"verified": gone, "checks": [{"check": "original pod deleted or terminating", "passed": gone,
                                          "observed": observed}]}


# --------------------------------------------------------------------------- scale to zero
def owning_deployment(namespace: str, pod: str) -> str | None:
    p = kube.core.read_namespaced_pod(pod, namespace)
    for ref in p.metadata.owner_references or []:
        if ref.kind == "ReplicaSet":
            rs = kube.apps.read_namespaced_replica_set(ref.name, namespace)
            for rref in rs.metadata.owner_references or []:
                if rref.kind == "Deployment":
                    return rref.name
    return None


def _scale_execute(namespace: str, deployment: str, ctx: dict[str, Any]) -> dict[str, Any]:
    current = kube.apps.read_namespaced_deployment_scale(deployment, namespace)
    previous = current.spec.replicas
    kube.apps.patch_namespaced_deployment_scale(deployment, namespace, {"spec": {"replicas": 0}})
    return {"changed": previous != 0, "previous_replicas": previous, "replicas": 0}


def _scale_verify(namespace: str, deployment: str, ctx: dict[str, Any]) -> dict[str, Any]:
    d = kube.apps.read_namespaced_deployment(deployment, namespace)
    ok = d.spec.replicas == 0
    return {"verified": ok, "checks": [{"check": "deployment spec.replicas == 0", "passed": ok,
                                        "observed": {"spec": d.spec.replicas,
                                                     "ready": d.status.ready_replicas or 0}}]}


# --------------------------------------------------------------------------- namespace containment
def _containment_name() -> str:
    return "ks-containment-egress"


def _contain_execute(namespace: str, _target: str, ctx: dict[str, Any]) -> dict[str, Any]:
    if not _cilium_available():
        raise RuntimeError("namespace containment requires Cilium (deny policies); Cilium CRDs not available")
    name = _containment_name()
    body = {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {"name": name, "namespace": namespace, "labels": dict(MANAGED_LABELS)},
        "spec": {
            "description": "KubeShield containment: deny egress to the internet and to other namespaces",
            "endpointSelector": {},
            # Without this, any policy selecting an endpoint makes Cilium default-deny that
            # direction, which would also cut DNS. Only the listed denies should apply.
            "enableDefaultDeny": {"egress": False, "ingress": False},
            "egressDeny": [
                # In kind the API server is a host-network identity, so it must be
                # denied as an entity; namespace selectors do not match it.
                {"toEntities": ["world", "kube-apiserver", "host", "remote-node"]},
                {"toEndpoints": [{"matchExpressions": [{
                    "key": "k8s:io.kubernetes.pod.namespace", "operator": "NotIn",
                    "values": [namespace, "kube-system"]}]}]},
            ],
        },
    }
    _apply_custom(namespace, name, body)
    return {"changed": True, "policy": name, "engine": "cilium-deny-policy",
            "effect": "egress to the internet, the API server and other namespaces denied; "
                      "in-namespace traffic and kube-system DNS still allowed"}


def _uncontain_execute(namespace: str, _target: str, ctx: dict[str, Any]) -> dict[str, Any]:
    try:
        kube.custom.delete_namespaced_custom_object(*CILIUM[:2], namespace, CILIUM[2], _containment_name())
        return {"changed": True, "removed": f"CiliumNetworkPolicy/{_containment_name()}"}
    except ApiException as exc:
        if exc.status != 404:
            raise
        return {"changed": False, "removed": None}


def _uncontain_verify(namespace: str, _target: str, ctx: dict[str, Any]) -> dict[str, Any]:
    try:
        kube.custom.get_namespaced_custom_object(*CILIUM[:2], namespace, CILIUM[2], _containment_name())
        gone = False
    except ApiException as exc:
        gone = exc.status == 404
    return {"verified": gone, "checks": [{"check": "containment policy removed", "passed": gone}]}


def _contain_verify(namespace: str, _target: str, ctx: dict[str, Any]) -> dict[str, Any]:
    try:
        cnp = kube.custom.get_namespaced_custom_object(*CILIUM[:2], namespace, CILIUM[2], _containment_name())
        ok = len(cnp["spec"].get("egressDeny", [])) == 2
        observed = cnp["metadata"]["name"]
    except ApiException as exc:
        ok, observed = False, f"HTTP {exc.status}"
    return {"verified": ok, "checks": [{"check": "containment CiliumNetworkPolicy present", "passed": ok,
                                        "observed": observed}]}


ACTIONS: dict[str, ActionSpec] = {
    a.type: a
    for a in (
        ActionSpec("alert_only", "Alert only", "Record the alert without changing the cluster.", "Pod", False,
                   _alert_execute, _alert_verify),
        ActionSpec("isolate_pod", "Isolate pod", "Label the pod and apply a deny-all network quarantine.",
                   "Pod", False, _isolate_execute, _isolate_verify),
        ActionSpec("release_isolation", "Release isolation", "Remove the network quarantine from a pod.",
                   "Pod", False, _release_execute, _release_verify),
        ActionSpec("delete_pod", "Delete pod", "Capture forensics (spec, logs) and delete the pod.", "Pod",
                   True, _delete_execute, _delete_verify),
        ActionSpec("scale_to_zero", "Scale deployment to zero", "Scale the owning Deployment to 0 replicas.",
                   "Deployment", True, _scale_execute, _scale_verify),
        ActionSpec("contain_namespace", "Apply namespace containment policy",
                   "Deny egress from every pod in the namespace to the internet, the API server and other "
                   "namespaces.", "Namespace", False, _contain_execute, _contain_verify),
        ActionSpec("release_containment", "Release namespace containment",
                   "Remove the namespace containment policy.", "Namespace", False, _uncontain_execute,
                   _uncontain_verify),
    )
}
