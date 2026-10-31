from kubeshield.k8s import posture


def deployment(pod_spec, name="web", ns="lab-apps"):
    return {"metadata": {"name": name, "namespace": ns}, "spec": {"template": {"spec": pod_spec}}}


HARDENED = {
    "automountServiceAccountToken": False,
    "securityContext": {"runAsNonRoot": True, "runAsUser": 10001},
    "containers": [{
        "name": "app", "image": "registry.example/app:1.2.3",
        "resources": {"limits": {"cpu": "100m", "memory": "64Mi"}},
        "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                            "capabilities": {"drop": ["ALL"]}},
    }],
}


def ids(findings):
    return sorted(f.check_id for f in findings)


def test_hardened_workload_has_no_findings():
    assert posture.check_workload("Deployment", deployment(HARDENED)) == []


def test_insecure_workload_flags_everything():
    spec = {
        "hostPID": True, "hostIPC": True, "hostNetwork": True,
        "volumes": [{"name": "etc", "hostPath": {"path": "/etc"}}],
        "containers": [{"name": "c", "image": "nginx", "securityContext": {
            "privileged": True, "runAsUser": 0, "capabilities": {"add": ["SYS_ADMIN", "NET_BIND_SERVICE"]}}}],
    }
    found = posture.check_workload("Deployment", deployment(spec))
    assert ids(found) == ["KS-POD-001", "KS-POD-002", "KS-POD-003", "KS-POD-004", "KS-POD-005", "KS-POD-006",
                          "KS-POD-007", "KS-POD-009", "KS-POD-010", "KS-POD-011", "KS-POD-012"]
    caps = next(f for f in found if f.check_id == "KS-POD-006")
    assert caps.evidence["capabilities"] == ["SYS_ADMIN"] and caps.container == "c"
    hostpath = next(f for f in found if f.check_id == "KS-POD-005")
    assert hostpath.severity == "critical"


def test_latest_tag_and_digest_rules():
    def tag_findings(image):
        spec = {**HARDENED, "containers": [{**HARDENED["containers"][0], "image": image}]}
        return [f for f in posture.check_workload("Deployment", deployment(spec)) if f.check_id == "KS-POD-011"]

    assert tag_findings("nginx:latest") and tag_findings("registry:5000/nginx")
    assert not tag_findings("registry:5000/nginx:1.27") and not tag_findings("nginx@sha256:" + "a" * 64)


def test_fingerprint_is_stable_and_distinct():
    a = posture.check_workload("Deployment", deployment({"hostPID": True, **HARDENED}))[0]
    b = posture.check_workload("Deployment", deployment({"hostPID": True, **HARDENED}))[0]
    c = posture.check_workload("Deployment", deployment({"hostPID": True, **HARDENED}, name="other"))[0]
    assert a.fingerprint == b.fingerprint != c.fingerprint


def test_rbac_wildcard_cluster_binding_is_critical():
    roles = [("ClusterRole", None, {"metadata": {"name": "god"}, "rules": [
        {"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]}),
        ("Role", "lab-legacy", {"metadata": {"name": "reader"}, "rules": [
            {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list"]}]})]
    bindings = [
        ("ClusterRoleBinding", None, {"metadata": {"name": "b1"}, "roleRef": {"kind": "ClusterRole", "name": "god"},
                                      "subjects": [{"kind": "ServiceAccount", "name": "app",
                                                    "namespace": "lab-apps"}]}),
        ("RoleBinding", "lab-legacy", {"metadata": {"name": "b2", "namespace": "lab-legacy"},
                                       "roleRef": {"kind": "Role", "name": "reader"},
                                       "subjects": [{"kind": "ServiceAccount", "name": "legacy",
                                                     "namespace": "lab-legacy"}]}),
        ("ClusterRoleBinding", None, {"metadata": {"name": "sys"}, "roleRef": {"kind": "ClusterRole",
                                                                               "name": "cluster-admin"},
                                      "subjects": [{"kind": "Group", "name": "system:masters"}]}),
    ]
    found = posture.check_rbac(roles, bindings)
    assert len(found) == 2
    crit = next(f for f in found if f.resource_name == "b1")
    assert crit.severity == "critical" and "wildcard verbs on wildcard resources" in crit.evidence["risks"]
    med = next(f for f in found if f.resource_name == "b2")
    assert med.severity == "medium" and med.evidence["risks"] == ["can read secrets"]


def test_network_isolation():
    namespaces = [{"metadata": {"name": n}} for n in ("lab-apps", "lab-payments", "kube-system", "lab-x")]
    k8s = [{"metadata": {"name": "default-deny", "namespace": "lab-payments"},
            "spec": {"podSelector": {}, "policyTypes": ["Ingress"]}},
           {"metadata": {"name": "partial", "namespace": "lab-apps"},
            "spec": {"podSelector": {"matchLabels": {"app": "x"}}}}]
    cilium = [{"metadata": {"name": "c", "namespace": "lab-x"}, "spec": {"endpointSelector": {}, "ingress": []}}]
    found = posture.check_network_isolation(namespaces, k8s, cilium)
    assert [f.resource_name for f in found] == ["lab-apps"]
