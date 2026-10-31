"""Thin, lazily initialised Kubernetes API access with laboratory guards."""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

from kubernetes import client, config
from kubernetes.client import ApiException

from kubeshield.config import get_settings

log = logging.getLogger(__name__)


class KubeUnavailable(RuntimeError):
    pass


class LabGuardError(PermissionError):
    """Raised when an action targets a namespace outside the isolated laboratory."""


class _Kube:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._api: client.ApiClient | None = None
        self.last_error: str | None = None
        self._lab_cache: dict[str, tuple[float, bool]] = {}

    def api(self) -> client.ApiClient:
        with self._lock:
            if self._api is not None:
                return self._api
            s = get_settings()
            if s.kube_mode == "disabled":
                raise KubeUnavailable("Kubernetes integration disabled (KUBESHIELD_KUBE_MODE=disabled)")
            try:
                if s.kube_mode == "in-cluster":
                    config.load_incluster_config()
                    self._api = client.ApiClient()
                else:
                    self._api = config.new_client_from_config(context=s.kube_context)
                self.last_error = None
            except Exception as exc:  # noqa: BLE001 - surface any config problem
                self.last_error = str(exc)
                raise KubeUnavailable(f"cannot load Kubernetes configuration: {exc}") from exc
            return self._api

    def reset(self) -> None:
        with self._lock:
            self._api = None

    @property
    def core(self) -> client.CoreV1Api:
        return client.CoreV1Api(self.api())

    @property
    def apps(self) -> client.AppsV1Api:
        return client.AppsV1Api(self.api())

    @property
    def rbac(self) -> client.RbacAuthorizationV1Api:
        return client.RbacAuthorizationV1Api(self.api())

    @property
    def networking(self) -> client.NetworkingV1Api:
        return client.NetworkingV1Api(self.api())

    @property
    def custom(self) -> client.CustomObjectsApi:
        return client.CustomObjectsApi(self.api())

    @property
    def version(self) -> client.VersionApi:
        return client.VersionApi(self.api())

    def available(self) -> tuple[bool, str | None]:
        try:
            self.version.get_code(_request_timeout=5)
            return True, None
        except KubeUnavailable as exc:
            return False, str(exc)
        except Exception as exc:  # noqa: BLE001
            self.last_error = str(exc)
            return False, str(exc)

    def is_lab_namespace(self, namespace: str, *, use_cache: bool = True) -> bool:
        """True only when the namespace carries <lab_label>=true. Never cached for more than 10 s."""
        now = time.monotonic()
        cached = self._lab_cache.get(namespace)
        if use_cache and cached and now - cached[0] < 10:
            return cached[1]
        try:
            ns = self.core.read_namespace(namespace, _request_timeout=10)
        except ApiException as exc:
            if exc.status == 404:
                return False
            raise
        labels = ns.metadata.labels or {}
        result = labels.get(get_settings().lab_label) == "true"
        self._lab_cache[namespace] = (now, result)
        return result

    def require_lab_namespace(self, namespace: str) -> None:
        if not namespace or not self.is_lab_namespace(namespace, use_cache=False):
            raise LabGuardError(
                f"namespace '{namespace}' is not labelled {get_settings().lab_label}=true; "
                "KubeShield only acts inside the isolated laboratory"
            )

    def crd_available(self, group: str, version: str, plural: str) -> bool:
        try:
            self.custom.list_cluster_custom_object(group, version, plural, limit=1, _request_timeout=10)
            return True
        except Exception:  # noqa: BLE001 - missing CRD, RBAC denial or outage: treat as unavailable
            return False


kube = _Kube()


def sanitize(obj: Any) -> Any:
    """Serialise kubernetes client models to plain JSON-compatible data."""
    return client.ApiClient().sanitize_for_serialization(obj)
