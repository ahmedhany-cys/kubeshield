"""Controlled attack simulations against the isolated laboratory.

Each scenario performs a real action inside a lab namespace (exec into a lab
pod, or submit a workload to the API server) and then verifies the outcome
from telemetry that KubeShield actually received. A scenario only reports
"detected" when the expected security events exist in the database.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from kubernetes import client
from kubernetes.client import ApiException
from kubernetes.stream import stream
from sqlalchemy import select
from sqlalchemy.orm import Session

from kubeshield import audit
from kubeshield.db import after_commit, session_scope
from kubeshield.k8s.client import kube
from kubeshield.models import (
    ImageScan,
    PolicyViolation,
    PostureFinding,
    ResponseAction,
    SecurityEvent,
    SimulationRun,
    utcnow,
)

log = logging.getLogger(__name__)
_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ks-sim")
SYNCHRONOUS = False

APP_NS, DB_NS, LEGACY_NS = "lab-apps", "lab-payments", "lab-legacy"
SIM_LABELS = {"app.kubernetes.io/managed-by": "kubeshield-simulation"}
VULNERABLE_IMAGE = "docker.io/library/alpine:3.10.0"


@dataclass(frozen=True)
class Scenario:
    id: str
    title: str
    description: str
    objective: str
    target: str
    procedure: tuple[str, ...]
    expected_telemetry: str
    expected_detections: tuple[str, ...]
    expected_response: str
    techniques: tuple[str, ...]
    kind: str  # runtime | admission | posture | image
    run: Callable[[RunContext], None] = field(repr=False, compare=False)


class RunContext:
    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        self.steps: list[dict[str, Any]] = []
        self.checks: list[dict[str, Any]] = []
        self.evidence: dict[str, Any] = {}
        self.started = utcnow()
        self.target_pod: str | None = None
        self.target_ns: str | None = None
        self.outcome: str | None = None

    def step(self, title: str, **details: Any) -> None:
        self.steps.append({"at": utcnow().isoformat(), "title": title, **details})
        self._publish()

    def check(self, title: str, passed: bool, **observed: Any) -> bool:
        self.checks.append({"title": title, "passed": bool(passed), **observed})
        self._publish()
        return passed

    def _publish(self) -> None:
        """Persist progress so the UI can follow a running scenario."""
        with session_scope() as db:
            run = db.get(SimulationRun, self.run_id)
            if run is not None:
                run.steps, run.checks = list(self.steps), list(self.checks)


# --------------------------------------------------------------------------- helpers
def _running_pod(namespace: str, app: str) -> str:
    pods = kube.core.list_namespaced_pod(namespace, label_selector=f"app={app}").items
    for p in pods:
        statuses = p.status.container_statuses or []
        if p.status.phase == "Running" and p.metadata.deletion_timestamp is None and statuses and all(
                s.ready for s in statuses) and not (p.metadata.labels or {}).get("kubeshield.io/quarantine"):
            return p.metadata.name
    raise RuntimeError(f"no ready, unquarantined pod with app={app} in {namespace}; is the lab deployed?")


def exec_in_pod(namespace: str, pod: str, command: list[str], timeout: int = 20) -> dict[str, Any]:
    """Run a command in a lab pod through the Kubernetes exec API."""
    kube.require_lab_namespace(namespace)
    api = client.CoreV1Api(client.ApiClient(kube.api().configuration))  # stream() needs its own client
    resp = stream(api.connect_get_namespaced_pod_exec, pod, namespace, command=command, stderr=True,
                  stdin=False, stdout=True, tty=False, _preload_content=False)
    resp.run_forever(timeout=timeout)
    out, err = resp.read_stdout() or "", resp.read_stderr() or ""
    rc = resp.returncode
    resp.close()
    return {"command": command, "exit_code": rc, "stdout": out[-2000:], "stderr": err[-2000:]}


def wait_for_events(ctx: RunContext, rule_ids: tuple[str, ...], timeout: int = 45) -> dict[str, list[str]]:
    """Poll the database for events from the target pod for each expected rule."""
    since = ctx.started - timedelta(seconds=5)
    deadline = time.monotonic() + timeout
    found: dict[str, list[str]] = {r: [] for r in rule_ids}
    while time.monotonic() < deadline:
        with session_scope() as db:
            q = select(SecurityEvent.id, SecurityEvent.rule_id).where(
                SecurityEvent.timestamp >= since, SecurityEvent.rule_id.in_(rule_ids))
            if ctx.target_ns:
                q = q.where(SecurityEvent.namespace == ctx.target_ns)
            if ctx.target_pod:
                q = q.where(SecurityEvent.pod == ctx.target_pod)
            for eid, rid in db.execute(q):
                if eid not in found[rid]:
                    found[rid].append(eid)
        if all(found.values()):
            break
        time.sleep(2)
    return found


def verify_detections(ctx: RunContext, rule_ids: tuple[str, ...], timeout: int = 45) -> None:
    found = wait_for_events(ctx, rule_ids, timeout)
    for rid in rule_ids:
        ctx.check(f"Detection {rid} received from {ctx.target_ns}/{ctx.target_pod}", bool(found[rid]),
                  event_ids=found[rid][:5])
    ctx.evidence["event_ids"] = sorted({e for ids in found.values() for e in ids})
    hits = sum(1 for r in rule_ids if found[r])
    ctx.outcome = "detected" if hits == len(rule_ids) else ("partial" if hits else "missed")
    # Record the response the playbooks produced for this activity (if any).
    with session_scope() as db:
        evs = db.scalars(select(SecurityEvent).where(SecurityEvent.id.in_(ctx.evidence["event_ids"]))).all()
        incident_ids = sorted({e.incident_id for e in evs if e.incident_id})
        ctx.evidence["incident_ids"] = incident_ids
        actions = db.scalars(select(ResponseAction).where(ResponseAction.incident_id.in_(incident_ids))).all()
        ctx.evidence["response_actions"] = [
            {"id": a.id, "action": a.action_type, "status": a.status, "mode": a.mode} for a in actions]


# --------------------------------------------------------------------------- runtime scenarios
def _runtime(app_ns: str, app: str, command: list[str], rules: tuple[str, ...]) -> Callable[[RunContext], None]:
    def run(ctx: RunContext) -> None:
        pod = _running_pod(app_ns, app)
        ctx.target_ns, ctx.target_pod = app_ns, pod
        result = exec_in_pod(app_ns, pod, command)
        ctx.step("Executed attack command in lab pod", pod=f"{app_ns}/{pod}", **result)
        verify_detections(ctx, rules)

    return run


def _unauthorized_comm(ctx: RunContext) -> None:
    pod = _running_pod(APP_NS, "storefront")
    ctx.target_ns, ctx.target_pod = APP_NS, pod
    cmd = ["sh", "-c", f"nc -w 3 payments-db.{DB_NS}.svc.cluster.local 5432 </dev/null; echo exit=$?"]
    result = exec_in_pod(APP_NS, pod, cmd)
    ctx.step("Attempted connection from storefront to payments-db:5432", **result)
    ctx.check("Connection was not established (network policy enforced)",
              "exit=0" not in result["stdout"], stdout=result["stdout"])
    verify_detections(ctx, ("ks.002", "ks.007", "ks.101"), timeout=60)


def _privileged_deploy(ctx: RunContext) -> None:
    ctx.target_ns = APP_NS
    name = f"sim-privileged-{ctx.run_id[-6:]}"
    ctx.target_pod = name
    pod = {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": APP_NS, "labels": dict(SIM_LABELS)},
        "spec": {"hostPID": True, "containers": [{
            "name": "escape", "image": "docker.io/library/busybox:1.37", "command": ["sleep", "60"],
            "securityContext": {"privileged": True}}]},
    }
    kube.require_lab_namespace(APP_NS)
    try:
        kube.core.create_namespaced_pod(APP_NS, pod)
        ctx.step("Submitted privileged hostPID pod", admitted=True)
        ctx.check("Admission controller blocked the privileged pod", False)
        kube.core.delete_namespaced_pod(name, APP_NS)
        ctx.outcome = "missed"
        return
    except ApiException as exc:
        blocked = exc.status in (400, 403) and "kyverno" in (exc.body or "").lower()
        ctx.step("Submitted privileged hostPID pod", admitted=False, http_status=exc.status,
                 response=(exc.body or "")[:1500])
        ctx.check("Kyverno denied the request at admission", blocked, http_status=exc.status)
    # Confirm KubeShield recorded the denial from Kyverno's own event stream.
    from kubeshield.policy import kyverno

    deadline = time.monotonic() + 45
    rows: list[str] = []
    while time.monotonic() < deadline and not rows:
        with session_scope() as db:
            try:
                kyverno.sync(db)
            except Exception as exc:  # noqa: BLE001
                ctx.step("Kyverno sync failed", error=str(exc))
            rows = list(db.scalars(select(PolicyViolation.id).where(
                PolicyViolation.source == "admission", PolicyViolation.resource_name == name)))
        if not rows:
            time.sleep(3)
    ctx.check("Admission denial recorded as policy violation", bool(rows), violation_ids=rows[:10])
    found = wait_for_events(ctx, ("ks.201",), timeout=10)
    ctx.check("Security event ks.201 raised for the blocked deployment", bool(found["ks.201"]),
              event_ids=found["ks.201"])
    ctx.evidence["event_ids"] = found["ks.201"]
    ctx.outcome = "blocked" if all(c["passed"] for c in ctx.checks) else "partial"


def _dangerous_config(ctx: RunContext) -> None:
    ctx.target_ns = LEGACY_NS
    name = f"sim-dangerous-{ctx.run_id[-6:]}"
    ctx.target_pod = name
    deploy = {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": name, "namespace": LEGACY_NS, "labels": dict(SIM_LABELS)},
        "spec": {"replicas": 1, "selector": {"matchLabels": {"app": name}}, "template": {
            "metadata": {"labels": {"app": name, **SIM_LABELS}},
            "spec": {"hostNetwork": True, "hostPID": True, "containers": [{
                "name": "agent", "image": "docker.io/library/busybox:1.37", "command": ["sleep", "3600"],
                "securityContext": {"capabilities": {"add": ["NET_ADMIN", "SYS_PTRACE"]}}}]}}},
    }
    kube.require_lab_namespace(LEGACY_NS)
    kube.apps.create_namespaced_deployment(LEGACY_NS, deploy)
    ctx.step("Created insecure Deployment in audit-mode namespace", deployment=f"{LEGACY_NS}/{name}")
    try:
        from kubeshield.k8s import inventory

        expected = {"KS-POD-002", "KS-POD-004", "KS-POD-006"}
        found: set[str] = set()
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and found != expected:
            with session_scope() as db:
                inventory.collect(db)
                found = set(db.scalars(select(PostureFinding.check_id).where(
                    PostureFinding.namespace == LEGACY_NS, PostureFinding.resource_name == name,
                    PostureFinding.status == "open")))
            if found != expected:
                time.sleep(5)
        ctx.check("Posture scanner flagged hostPID, hostNetwork and dangerous capabilities",
                  expected <= found, findings=sorted(found))
        from kubeshield.policy import kyverno

        policies: set[str] = set()
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline and not policies:
            with session_scope() as db:
                kyverno.sync(db)
                policies = set(db.scalars(select(PolicyViolation.policy).where(
                    PolicyViolation.namespace == LEGACY_NS, PolicyViolation.resource_name == name,
                    PolicyViolation.status == "open")))
            if not policies:
                time.sleep(5)
        ctx.check("Kyverno audit-mode PolicyReport recorded violations", bool(policies),
                  policies=sorted(policies))
        ctx.evidence["findings"], ctx.evidence["policies"] = sorted(found), sorted(policies)
        ctx.outcome = "detected" if all(c["passed"] for c in ctx.checks) else "partial"
    finally:
        kube.apps.delete_namespaced_deployment(name, LEGACY_NS)
        ctx.step("Removed the insecure Deployment", deployment=f"{LEGACY_NS}/{name}")


def _vulnerable_image(ctx: RunContext) -> None:
    from kubeshield.scanners import trivy

    ctx.target_ns = LEGACY_NS
    with session_scope() as db:
        scan = trivy.queue_scan(db, VULNERABLE_IMAGE, "simulation", f"simulation:{ctx.run_id}")
        scan_id = scan.id
    ctx.step("Queued Trivy scan of the image before deployment", image=VULNERABLE_IMAGE, scan_id=scan_id)
    deadline = time.monotonic() + 900
    status, counts = "queued", {}
    while time.monotonic() < deadline:
        with session_scope() as db:
            s = db.get(ImageScan, scan_id)
            status, counts, error = s.status, dict(s.counts or {}), s.error
        if status in ("succeeded", "failed"):
            break
        time.sleep(5)
    ctx.check("Trivy scan completed", status == "succeeded", status=status, error=error)
    risky = counts.get("critical", 0) + counts.get("high", 0)
    ctx.check("Critical/high vulnerabilities identified before deployment", risky > 0, counts=counts)
    ctx.evidence["scan_id"] = scan_id
    ctx.outcome = "detected" if all(c["passed"] for c in ctx.checks) else (
        "error" if status != "succeeded" else "missed")


SCENARIOS: dict[str, Scenario] = {s.id: s for s in (
    Scenario(
        "shell-in-container", "Unexpected shell execution",
        "An attacker with exec access (or an RCE in the web app) opens a shell in the storefront pod.",
        "Prove that interactive shells inside workload containers are detected.",
        f"{APP_NS}/storefront", ("kubectl exec <storefront pod> -- sh -c 'id; uname -a'",),
        "Falco execve event for /bin/sh whose parent is the container runtime.",
        ("ks.001",), "Alert-only playbook records the activity; analyst reviews.", ("T1059.004", "T1609"),
        "runtime", _runtime(APP_NS, "storefront", ["sh", "-c", "id; uname -a"], ("ks.001",)),
    ),
    Scenario(
        "sensitive-file-access", "Sensitive file access",
        "The attacker tries to read /etc/shadow inside the storefront container.",
        "Detect attempts to read local credential stores.",
        f"{APP_NS}/storefront", ("kubectl exec <storefront pod> -- sh -c 'cat /etc/shadow'",),
        "Falco openat event on /etc/shadow (attempted read, even if permission is denied).",
        ("ks.003",), "Quarantine playbook requests approval to isolate the pod.", ("T1003.008",),
        "runtime", _runtime(APP_NS, "storefront", ["sh", "-c", "cat /etc/shadow >/dev/null 2>&1; true"],
                            ("ks.003",)),
    ),
    Scenario(
        "service-account-token-access", "Service account token access",
        "The attacker reads the projected service account token to reuse it against the API server.",
        "Detect theft of Kubernetes API credentials from a pod.",
        f"{APP_NS}/storefront",
        ("kubectl exec <storefront pod> -- cat /var/run/secrets/kubernetes.io/serviceaccount/token",),
        "Falco openat event on the projected token path.",
        ("ks.004",), "Quarantine and delete-pod playbooks request analyst approval.", ("T1528", "T1552.001"),
        "runtime", _runtime(APP_NS, "storefront",
                            ["sh", "-c", "cat /var/run/secrets/kubernetes.io/serviceaccount/token >/dev/null"],
                            ("ks.004",)),
    ),
    Scenario(
        "suspicious-process", "Suspicious process execution",
        "The attacker stages a copy of busybox in /tmp, runs it, and marks a file setuid for persistence.",
        "Detect dropped-binary execution and setuid planting.",
        f"{APP_NS}/storefront",
        ("cp /bin/busybox /tmp/.cache-helper && /tmp/.cache-helper true",
         "touch /tmp/.suid && chmod u+s /tmp/.suid"),
        "Falco execve from /tmp and fchmodat with S_ISUID.",
        ("ks.006", "ks.005"), "Quarantine playbook (critical) requests approval.", ("T1105", "T1548.001"),
        "runtime", _runtime(APP_NS, "storefront", [
            "sh", "-c", "cp /bin/busybox /tmp/.cache-helper && /tmp/.cache-helper true; "
                        "touch /tmp/.suid && chmod u+s /tmp/.suid; rm -f /tmp/.cache-helper /tmp/.suid"],
            ("ks.006", "ks.005")),
    ),
    Scenario(
        "host-path-access", "Sensitive host path access",
        "From the legacy pod that mounts the node's /etc, the attacker reads node configuration.",
        "Detect use of hostPath mounts to reach the node filesystem.",
        f"{LEGACY_NS}/legacy-reporting", ("kubectl exec <legacy pod> -- cat /host/etc/os-release",),
        "Falco openat event below /host/.", ("ks.008",),
        "Quarantine and delete-pod playbooks request approval.", ("T1611",),
        "runtime", _runtime(LEGACY_NS, "legacy-reporting", ["sh", "-c", "cat /host/etc/os-release >/dev/null"],
                            ("ks.008",)),
    ),
    Scenario(
        "unauthorized-pod-communication", "Unauthorized pod communication",
        "The compromised storefront pod probes the payments database in another namespace.",
        "Show that namespace isolation blocks the connection and that the attempt is detected.",
        f"{APP_NS}/storefront -> {DB_NS}/payments-db:5432",
        ("kubectl exec <storefront pod> -- nc -w 3 payments-db.lab-payments.svc.cluster.local 5432",),
        "Falco execve of nc and connect() to port 5432; Hubble flow with verdict DROPPED (POLICY_DENIED).",
        ("ks.002", "ks.007", "ks.101"), "Connection blocked by Cilium; alert-only playbook records the probe.",
        ("T1046",), "runtime", _unauthorized_comm,
    ),
    Scenario(
        "privileged-container-deployment", "Privileged container deployment",
        "An attacker with create-pod rights submits a privileged, hostPID pod to escape to the node.",
        "Prove the admission policy blocks the pod and that the attempt is recorded.",
        f"{APP_NS} (enforce mode)", ("kubectl run with securityContext.privileged=true and hostPID=true",),
        "Kubernetes API denial from Kyverno; Kyverno PolicyViolation event.", ("ks.201",),
        "Blocked at admission; no workload created.", ("T1610", "T1611"), "admission", _privileged_deploy,
    ),
    Scenario(
        "dangerous-configuration", "Dangerous Kubernetes configuration",
        "A Deployment with hostNetwork, hostPID and NET_ADMIN/SYS_PTRACE is created in an audit-mode namespace.",
        "Show that posture scanning and Kyverno audit reports identify the dangerous configuration.",
        f"{LEGACY_NS} (audit mode)", ("kubectl apply an insecure Deployment", "wait for scans", "delete it"),
        "KubeShield posture findings and Kyverno PolicyReport results.", (),
        "Findings with remediation guidance; Deployment removed after verification.", ("T1610", "T1611"),
        "posture", _dangerous_config,
    ),
    Scenario(
        "vulnerable-image-deployment", "Vulnerable container image",
        f"Before deploying {VULNERABLE_IMAGE}, the pre-deployment gate scans it with Trivy.",
        "Identify critical/high CVEs in an outdated base image before it reaches the cluster.",
        VULNERABLE_IMAGE, (f"trivy image {VULNERABLE_IMAGE}",),
        "Trivy vulnerability report with CVE, package, versions and CVSS.", (),
        "Deployment should be rejected by the release process until the image is rebuilt.", (),
        "image", _vulnerable_image,
    ),
)}


def start(db: Session, scenario_id: str, actor: str) -> SimulationRun:
    if scenario_id not in SCENARIOS:
        raise KeyError(scenario_id)
    running = db.scalar(select(SimulationRun).where(SimulationRun.status == "running"))
    if running is not None:
        raise RuntimeError(f"simulation {running.id} ({running.scenario_id}) is still running")
    run = SimulationRun(scenario_id=scenario_id, status="running", requested_by=actor)
    db.add(run)
    db.flush()
    audit.record(db, actor, "simulation.started", scenario_id, details={"run_id": run.id})
    after_commit(db, lambda rid=run.id: _execute(rid) if SYNCHRONOUS else _executor.submit(_execute, rid))
    return run


def _execute(run_id: str) -> None:
    with session_scope() as db:
        run = db.get(SimulationRun, run_id)
        scenario = SCENARIOS[run.scenario_id]
        ctx = RunContext(run_id)
        ctx.started = run.started_at
    error = None
    try:
        scenario.run(ctx)
    except Exception as exc:  # noqa: BLE001 - every failure is recorded on the run
        log.exception("simulation %s failed", run_id)
        error = str(exc)[:2000]
        ctx.outcome = "error"
    with session_scope() as db:
        run = db.get(SimulationRun, run_id)
        run.steps, run.checks, run.evidence = ctx.steps, ctx.checks, ctx.evidence
        run.outcome, run.error = ctx.outcome or "error", error
        run.status = "error" if error else "completed"
        run.finished_at = utcnow()
        incidents = ctx.evidence.get("incident_ids") or []
        run.incident_id = incidents[0] if incidents else None
        audit.record(db, run.requested_by, "simulation.finished", run.scenario_id,
                     details={"run_id": run_id, "outcome": run.outcome, "error": error})
