"""In-memory stand-ins for the Kubernetes API used by response tests."""

from types import SimpleNamespace

from kubernetes.client import ApiException

from kubeshield.k8s.client import LabGuardError


def _ns(**kw):
    return SimpleNamespace(**kw)


class FakeCore:
    def __init__(self, kube):
        self.kube = kube

    def read_namespaced_pod(self, name, namespace, **_):
        pod = self.kube.pods.get((namespace, name))
        if pod is None:
            raise ApiException(status=404, reason="Not Found")
        return pod

    def patch_namespaced_pod(self, name, namespace, body, **_):
        pod = self.read_namespaced_pod(name, namespace)
        for k, v in body["metadata"]["labels"].items():
            if v is None:
                pod.metadata.labels.pop(k, None)
            else:
                pod.metadata.labels[k] = v

    def read_namespaced_pod_log(self, name, namespace, **_):
        return "log line\n"

    def delete_namespaced_pod(self, name, namespace, **_):
        self.kube.pods.pop((namespace, name))


class FakeNetworking:
    def __init__(self, kube):
        self.kube = kube

    def create_namespaced_network_policy(self, namespace, body):
        self.kube.netpols[(namespace, body["metadata"]["name"])] = body

    def read_namespaced_network_policy(self, name, namespace):
        body = self.kube.netpols.get((namespace, name))
        if body is None:
            raise ApiException(status=404, reason="Not Found")
        spec = body["spec"]
        return _ns(spec=_ns(pod_selector=_ns(match_labels=spec["podSelector"]["matchLabels"]),
                            ingress=spec.get("ingress"), egress=spec.get("egress")))

    def delete_namespaced_network_policy(self, name, namespace):
        if self.kube.netpols.pop((namespace, name), None) is None:
            raise ApiException(status=404, reason="Not Found")


class FakeCustom:
    def __init__(self, kube):
        self.kube = kube

    def create_namespaced_custom_object(self, group, version, namespace, plural, body):
        body = {**body, "status": {"conditions": [{"type": "Valid", "status": "True"}]}}
        self.kube.cnps[(namespace, body["metadata"]["name"])] = body

    def get_namespaced_custom_object(self, group, version, namespace, plural, name):
        if plural == "ciliumendpoints":
            pod = self.kube.core.read_namespaced_pod(name, namespace)
            labels = [] if self.kube.stale_identity else [f"k8s:{k}={v}" for k, v in pod.metadata.labels.items()]
            return {"status": {"state": "ready", "identity": {"id": 4242, "labels": labels}}}
        body = self.kube.cnps.get((namespace, name))
        if body is None:
            raise ApiException(status=404, reason="Not Found")
        return body

    def delete_namespaced_custom_object(self, group, version, namespace, plural, name):
        if self.kube.cnps.pop((namespace, name), None) is None:
            raise ApiException(status=404, reason="Not Found")


class FakeKube:
    def __init__(self, lab_namespaces=("lab-apps",), cilium=True):
        self.lab = set(lab_namespaces)
        self.cilium = cilium
        self.stale_identity = False
        self.pods = {}
        self.netpols = {}
        self.cnps = {}
        self.core = FakeCore(self)
        self.networking = FakeNetworking(self)
        self.custom = FakeCustom(self)

    def add_pod(self, namespace, name):
        self.pods[(namespace, name)] = _ns(
            metadata=_ns(name=name, namespace=namespace, uid=f"uid-{name}", labels={"app": "x"},
                         owner_references=[], deletion_timestamp=None),
            spec=_ns(node_name="node-1", containers=[_ns(image="busybox:1.37")]),
        )

    def require_lab_namespace(self, namespace):
        if namespace not in self.lab:
            raise LabGuardError(f"namespace '{namespace}' is not part of the lab")

    def crd_available(self, *args):
        return self.cilium
