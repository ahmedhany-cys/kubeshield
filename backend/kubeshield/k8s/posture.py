"""Security posture checks over live Kubernetes objects.

Checks operate on plain dicts (the API's JSON form) so they are easy to unit
test with fixtures and never depend on client model classes.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any

DANGEROUS_CAPABILITIES = {
    "ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "SYS_RAWIO", "SYS_BOOT",
    "DAC_READ_SEARCH", "BPF", "PERFMON",
}
SENSITIVE_HOST_PATHS = ("/", "/etc", "/var/run", "/run", "/var/lib/kubelet", "/var/lib/docker",
                        "/var/lib/containerd", "/proc", "/sys", "/root", "/home")
SYSTEM_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease", "local-path-storage", "cilium-secrets"}


@dataclass
class Finding:
    check_id: str
    title: str
    category: str
    severity: str
    resource_kind: str
    namespace: str | None
    resource_name: str
    explanation: str
    remediation: str
    container: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        key = "|".join([self.check_id, self.resource_kind, self.namespace or "", self.resource_name,
                        self.container or ""])
        return hashlib.sha256(key.encode()).hexdigest()[:40]


def _containers(spec: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
    for key in ("initContainers", "containers", "ephemeralContainers"):
        for c in spec.get(key) or []:
            yield key, c


def _owner(meta: dict[str, Any]) -> str | None:
    refs = meta.get("ownerReferences") or []
    return f"{refs[0]['kind']}/{refs[0]['name']}" if refs else None


def check_workload(kind: str, obj: dict[str, Any]) -> list[Finding]:
    """Checks for a pod-bearing object (Pod, Deployment, DaemonSet, StatefulSet...)."""
    meta = obj.get("metadata", {})
    ns, name = meta.get("namespace"), meta.get("name", "?")
    spec = obj.get("spec", {})
    pod_spec = spec if kind == "Pod" else spec.get("template", {}).get("spec", {})
    out: list[Finding] = []

    def add(check_id, title, category, sev, explanation, remediation, container=None, **evidence):
        out.append(Finding(check_id, title, category, sev, kind, ns, name, explanation, remediation,
                           container, evidence))

    for flag, cid, sev, what in (
        ("hostPID", "KS-POD-002", "critical", "host PID namespace"),
        ("hostIPC", "KS-POD-003", "high", "host IPC namespace"),
        ("hostNetwork", "KS-POD-004", "high", "host network namespace"),
    ):
        if pod_spec.get(flag):
            add(cid, f"Shares the {what}", "host-isolation", sev,
                f"{flag}: true lets every container see and interact with node-level "
                f"{what.split()[1]} resources, which removes a core container isolation boundary.",
                f"Remove {flag} from the pod spec.", **{flag: True})

    for vol in pod_spec.get("volumes") or []:
        hp = vol.get("hostPath")
        if hp:
            path = hp.get("path", "")
            sensitive = any(path == p or path.startswith(p.rstrip("/") + "/") for p in SENSITIVE_HOST_PATHS)
            add("KS-POD-005", f"Mounts host path {path}", "host-isolation",
                "critical" if sensitive else "high",
                "hostPath volumes expose the node filesystem; write access to paths such as /etc, "
                "/var/run or the container runtime socket is a direct route to node compromise.",
                "Replace the hostPath volume with emptyDir, a ConfigMap/Secret or a PersistentVolumeClaim.",
                volume=vol.get("name"), path=path)

    pod_sc = pod_spec.get("securityContext") or {}
    sa_automount = pod_spec.get("automountServiceAccountToken")
    for _, c in _containers(pod_spec):
        cname = c.get("name")
        sc = c.get("securityContext") or {}
        if sc.get("privileged"):
            add("KS-POD-001", "Privileged container", "privileges", "critical",
                "A privileged container has all Linux capabilities and access to host devices; escaping to "
                "the node is trivial.", "Set securityContext.privileged: false and grant only the specific "
                "capability required.", cname, privileged=True)
        caps = {x.upper() for x in ((sc.get("capabilities") or {}).get("add") or [])}
        bad = sorted(caps & DANGEROUS_CAPABILITIES)
        if bad:
            add("KS-POD-006", f"Dangerous capabilities added: {', '.join(bad)}", "privileges", "high",
                "These capabilities grant kernel-level powers (mounts, raw devices, tracing other "
                "processes, network reconfiguration) that enable container escape.",
                "Drop ALL capabilities and add back only narrowly scoped ones such as NET_BIND_SERVICE.",
                cname, capabilities=bad)
        run_as_non_root = sc.get("runAsNonRoot", pod_sc.get("runAsNonRoot"))
        run_as_user = sc.get("runAsUser", pod_sc.get("runAsUser"))
        if run_as_user == 0 or not run_as_non_root:
            add("KS-POD-007", "Container may run as root", "privileges", "medium",
                "Without runAsNonRoot: true the container runs as whatever user the image specifies, "
                "commonly root, which amplifies the impact of any compromise.",
                "Set runAsNonRoot: true and a non-zero runAsUser; build images with a non-root USER.",
                cname, runAsNonRoot=run_as_non_root, runAsUser=run_as_user)
        if sc.get("allowPrivilegeEscalation") is not False and not sc.get("privileged"):
            add("KS-POD-008", "Privilege escalation not disabled", "privileges", "medium",
                "allowPrivilegeEscalation defaults to true, so setuid binaries can raise privileges "
                "inside the container.", "Set securityContext.allowPrivilegeEscalation: false.", cname,
                allowPrivilegeEscalation=sc.get("allowPrivilegeEscalation"))
        if not sc.get("readOnlyRootFilesystem"):
            add("KS-POD-009", "Writable root filesystem", "hardening", "low",
                "A writable root filesystem lets an attacker drop and execute tools inside the container.",
                "Set readOnlyRootFilesystem: true and mount emptyDir volumes for paths that need writes.",
                cname)
        limits = (c.get("resources") or {}).get("limits") or {}
        missing = [r for r in ("cpu", "memory") if r not in limits]
        if missing:
            add("KS-POD-010", f"Missing resource limits ({', '.join(missing)})", "resources", "medium",
                "Containers without limits can exhaust node resources (cryptomining, fork bombs) and "
                "degrade every other workload on the node.",
                "Set resources.limits.cpu and resources.limits.memory.", cname, missing=missing)
        image = c.get("image", "")
        last = image.rsplit("/", 1)[-1]
        if "@sha256:" not in image and (":" not in last or last.endswith(":latest")):
            add("KS-POD-011", "Mutable image tag", "supply-chain", "medium",
                "Images referenced by 'latest' or without a tag can change underneath the workload, "
                "breaking reproducibility and allowing silent image substitution.",
                "Pin the image to a version tag and preferably an @sha256 digest.", cname, image=image)
    if sa_automount is not False and kind != "Pod":
        add("KS-POD-012", "Service account token automatically mounted", "identity", "low",
            "Every container receives an API token. If the workload does not call the Kubernetes API, "
            "the token only helps an attacker.",
            "Set automountServiceAccountToken: false on the pod spec or service account.",
            serviceAccount=pod_spec.get("serviceAccountName", "default"))
    return out


# --------------------------------------------------------------------------- RBAC
DANGEROUS_VERBS = {"*", "escalate", "bind", "impersonate"}


def _rule_risks(rule: dict[str, Any]) -> list[str]:
    verbs = set(rule.get("verbs") or [])
    resources = set(rule.get("resources") or [])
    groups = set(rule.get("apiGroups") or [])
    risks = []
    if "*" in verbs and "*" in resources:
        risks.append("wildcard verbs on wildcard resources")
    elif "*" in resources and ("*" in groups or "" in groups):
        risks.append("wildcard resources")
    if verbs & {"escalate", "bind", "impersonate"}:
        risks.append(f"privilege escalation verbs ({', '.join(sorted(verbs & DANGEROUS_VERBS))})")
    if "secrets" in resources and verbs & {"get", "list", "watch", "*"}:
        risks.append("can read secrets")
    if "pods/exec" in resources and verbs & {"create", "*"}:
        risks.append("can exec into pods")
    if resources & {"pods", "deployments", "daemonsets"} and verbs & {"create", "*"}:
        risks.append("can create workloads")
    return risks


def check_rbac(
    roles: Iterable[tuple[str, str | None, dict[str, Any]]],
    bindings: Iterable[tuple[str, str | None, dict[str, Any]]],
) -> list[Finding]:
    """roles/bindings: (kind, namespace, obj). Flags subjects bound to risky roles."""
    role_risks: dict[tuple[str, str | None, str], list[str]] = {}
    for kind, ns, obj in roles:
        risks: list[str] = []
        for rule in obj.get("rules") or []:
            for r in _rule_risks(rule):
                if r not in risks:
                    risks.append(r)
        role_risks[(kind, ns, obj["metadata"]["name"])] = risks

    out: list[Finding] = []
    for bkind, bns, b in bindings:
        ref = b.get("roleRef", {})
        rkind, rname = ref.get("kind"), ref.get("name")
        risks = role_risks.get((rkind, None if rkind == "ClusterRole" else bns, rname), [])
        if rname == "cluster-admin":
            risks = ["cluster-admin"]
        if not risks:
            continue
        for subj in b.get("subjects") or []:
            sns = subj.get("namespace")
            if subj.get("kind") == "ServiceAccount" and (sns in SYSTEM_NAMESPACES or (sns or "").startswith(
                    ("kyverno", "falco", "cilium"))):
                continue
            if subj.get("kind") in ("Group", "User") and (subj.get("name", "").startswith("system:")):
                continue
            scope = "cluster-wide" if bkind == "ClusterRoleBinding" else f"in namespace {bns}"
            critical = "cluster-admin" in risks or any("wildcard" in r or "escalation" in r for r in risks)
            subject = f"{subj.get('kind')}/{(sns + '/') if sns else ''}{subj.get('name')}"
            out.append(Finding(
                "KS-RBAC-001", f"{subject} has risky permissions {scope}", "rbac",
                "critical" if critical and bkind == "ClusterRoleBinding" else ("high" if critical else "medium"),
                bkind, bns, b["metadata"]["name"],
                f"{subject} is bound to {rkind} '{rname}' {scope}, which grants: {'; '.join(risks)}. "
                "A compromised workload using this identity inherits these permissions.",
                "Replace the binding with a namespaced Role that grants only the verbs and resources the "
                "subject needs; avoid wildcards, secrets access and escalate/bind/impersonate.",
                evidence={"subject": subject, "role": f"{rkind}/{rname}", "risks": risks},
            ))
    return out


# --------------------------------------------------------------------------- network isolation
def check_network_isolation(
    namespaces: Iterable[dict[str, Any]],
    k8s_policies: Iterable[dict[str, Any]],
    cilium_policies: Iterable[dict[str, Any]] = (),
) -> list[Finding]:
    """Flag workload namespaces where no policy selects all pods for ingress."""
    covered: set[str] = set()
    for np in k8s_policies:
        spec = np.get("spec", {})
        if not (spec.get("podSelector") or {}).get("matchLabels") and not (spec.get("podSelector") or {}).get(
                "matchExpressions"):
            if "Ingress" in (spec.get("policyTypes") or ["Ingress"]):
                covered.add(np["metadata"]["namespace"])
    for cnp in cilium_policies:
        spec = cnp.get("spec", {})
        if spec.get("endpointSelector") == {} and ("ingress" in spec or "ingressDeny" in spec):
            covered.add(cnp["metadata"]["namespace"])
    out = []
    for ns in namespaces:
        name = ns["metadata"]["name"]
        if name in SYSTEM_NAMESPACES or name in covered:
            continue
        out.append(Finding(
            "KS-NET-001", "Namespace has no default-deny ingress policy", "network", "medium", "Namespace",
            None, name,
            "No NetworkPolicy selects every pod in this namespace for ingress, so any pod in the cluster "
            "can connect to its workloads (no namespace isolation).",
            "Add a default-deny ingress NetworkPolicy (podSelector: {}) and explicit allow rules.",
            evidence={"namespace": name},
        ))
    return out
