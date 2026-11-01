#!/usr/bin/env python3
"""End-to-end validation against a running KubeShield laboratory.

DETECT -> INVESTIGATE -> RESPOND -> VERIFY

1. Runs every attack scenario through the KubeShield API and requires the
   expected outcome (the API itself verifies telemetry for each run).
2. For the service-account-token scenario, approves the playbook's isolation
   request, waits for datapath-verified enforcement, then proves containment
   with real connections from and to the quarantined pod, checks the incident
   audit trail, and releases the quarantine.
3. Writes docs/validation/detection-validation-report.{md,json} from the
   recorded results. Nothing in the report is typed by hand.

Usage: python3 e2e/run_e2e.py [--url http://127.0.0.1:8080] [--only scenario-id ...]
Requires: kubectl context kind-kubeshield-lab, httpx.
"""

from __future__ import annotations

import argparse
import base64
import json
import subprocess  # noqa: S404 - fixed kubectl argv lists
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import httpx

CTX = "kind-kubeshield-lab"
ROOT = Path(__file__).resolve().parent.parent
EXPECTED = {
    "shell-in-container": "detected",
    "sensitive-file-access": "detected",
    "service-account-token-access": "detected",
    "suspicious-process": "detected",
    "host-path-access": "detected",
    "unauthorized-pod-communication": "detected",
    "privileged-container-deployment": "blocked",
    "dangerous-configuration": "detected",
    "vulnerable-image-deployment": "detected",
}
H = {"X-Requested-With": "kubeshield"}


def kubectl(*args: str, check: bool = True, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["kubectl", "--context", CTX, *args], capture_output=True, text=True,  # noqa: S603,S607
                          timeout=timeout, check=check)


def admin_password() -> str:
    raw = kubectl("-n", "kubeshield-system", "get", "secret", "kubeshield-secrets",
                  "-o", "jsonpath={.data.admin-password}").stdout
    return base64.b64decode(raw).decode()


def wait(predicate, timeout: int, interval: float = 3.0, what: str = "condition"):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    raise TimeoutError(f"timed out waiting for {what}")


def can_connect(namespace: str, pod: str, url: str) -> bool:
    r = kubectl("-n", namespace, "exec", pod, "--", "wget", "-q", "-T", "3", "-O", "/dev/null", url,
                check=False, timeout=30)
    return r.returncode == 0


def run_scenario(c: httpx.Client, scenario: str) -> dict:
    run = c.post("/api/v1/simulations/runs", json={"scenario_id": scenario}, headers=H)
    run.raise_for_status()
    rid = run.json()["id"]
    return wait(lambda: (lambda r: r if r["status"] != "running" else None)(
        c.get(f"/api/v1/simulations/runs/{rid}").json()), timeout=900, what=f"run {rid}")


def response_flow(c: httpx.Client, run: dict) -> dict:
    """Approve isolation for the incident created by the token-theft scenario and verify containment."""
    out: dict = {"checks": []}

    def check(title: str, passed: bool, **obs) -> None:
        out["checks"].append({"title": title, "passed": bool(passed), **obs})

    incident_id = run["incident_id"]
    check("Scenario produced an incident", incident_id is not None, incident_id=incident_id)
    inc = c.get(f"/api/v1/incidents/{incident_id}").json()
    pod, ns = inc["pod"], inc["namespace"]
    isolate = next((a for a in inc["actions"] if a["action_type"] == "isolate_pod"), None)
    check("Playbook requested isolation and waited for approval (safe default)",
          isolate is not None and isolate["status"] == "pending_approval",
          status=isolate and isolate["status"])
    if isolate is None:
        return out
    if isolate["status"] == "pending_approval":
        r = c.post(f"/api/v1/responses/{isolate['id']}/decision",
                   json={"approve": True, "note": "e2e: approve quarantine"}, headers=H)
        check("Analyst approval accepted", r.status_code == 200, http_status=r.status_code)
    final = wait(lambda: (lambda a: a if a["status"] not in ("approved", "executing") else None)(
        c.get(f"/api/v1/responses/{isolate['id']}").json()), timeout=180, what="isolation")
    check("Isolation succeeded with datapath-verified enforcement", final["status"] == "succeeded",
          status=final["status"], verification=final["verification"], error=final["error"])

    catalog = kubectl("-n", "lab-apps", "get", "pod", "-l", "app=catalog",
                      "-o", "jsonpath={.items[0].metadata.name}").stdout
    pod_ip = kubectl("-n", ns, "get", "pod", pod, "-o", "jsonpath={.status.podIP}").stdout
    check("Quarantined pod can no longer reach other services (egress blocked)",
          not can_connect(ns, pod, "http://catalog.lab-apps.svc.cluster.local:8080/"))
    check("Other pods can no longer reach the quarantined pod (ingress blocked)",
          not can_connect("lab-apps", catalog, f"http://{pod_ip}:8080/"))

    inc = c.get(f"/api/v1/incidents/{incident_id}").json()
    trail = [e["action"] for e in inc["audit_trail"]]
    check("Incident marked contained", inc["status"] == "contained", status=inc["status"])
    check("Audit trail records request, approval and outcome",
          all(a in trail for a in ("response.pending_approval", "response.approved", "response.succeeded")),
          trail=trail)

    rel = c.post("/api/v1/responses", json={"action_type": "release_isolation", "namespace": ns, "name": pod,
                                            "incident_id": incident_id, "reason": "e2e cleanup"}, headers=H)
    rel_id = rel.json()["id"]
    released = wait(lambda: (lambda a: a if a["status"] not in ("approved", "executing") else None)(
        c.get(f"/api/v1/responses/{rel_id}").json()), timeout=120, what="release")
    check("Quarantine released", released["status"] == "succeeded", status=released["status"])
    restored = wait(lambda: can_connect(ns, pod, "http://catalog.lab-apps.svc.cluster.local:8080/") or None,
                    timeout=120, interval=5, what="connectivity restore")
    check("Connectivity restored after release", bool(restored))
    c.post(f"/api/v1/incidents/{incident_id}/status", json={"status": "resolved", "note": "e2e"}, headers=H)
    out["incident_id"], out["action_id"] = incident_id, isolate["id"]
    return out


def containment_flow(c: httpx.Client) -> dict:
    """Contain lab-payments and prove which connections the namespace keeps and loses."""
    out: dict = {"checks": []}

    def check(title: str, passed: bool, **obs) -> None:
        out["checks"].append({"title": title, "passed": bool(passed), **obs})

    legacy = kubectl("-n", "lab-legacy", "get", "pod", "-l", "app=legacy-reporting",
                     "-o", "jsonpath={.items[0].metadata.name}").stdout
    kubectl("-n", "lab-legacy", "exec", legacy, "--", "sh", "-c",
            "mkdir -p /tmp/w && echo legacy > /tmp/w/index.html && (httpd -p 9000 -h /tmp/w || true)")
    legacy_ip = kubectl("-n", "lab-legacy", "get", "pod", legacy, "-o", "jsonpath={.status.podIP}").stdout
    client = kubectl("-n", "lab-payments", "get", "pod", "-l", "app=payments-api",
                     "-o", "jsonpath={.items[0].metadata.name}").stdout

    def probe() -> dict[str, bool]:
        script = (
            "nslookup payments-db.lab-payments.svc.cluster.local >/dev/null 2>&1 && echo dns=1 || echo dns=0;"
            "nc -w 3 payments-db 5432 </dev/null >/dev/null 2>&1 && echo same=1 || echo same=0;"
            "nc -w 3 kubernetes.default.svc 443 </dev/null >/dev/null 2>&1 && echo api=1 || echo api=0;"
            f"nc -w 3 {legacy_ip} 9000 </dev/null >/dev/null 2>&1 && echo cross=1 || echo cross=0"
        )
        res = kubectl("-n", "lab-payments", "exec", client, "--", "sh", "-c", script, check=False).stdout
        return {k: v == "1" for k, v in (line.split("=") for line in res.split() if "=" in line)}

    before = probe()
    check("Baseline: DNS, same-namespace, API server and cross-namespace reachable", all(before.values()),
          observed=before)
    r = c.post("/api/v1/responses", json={"action_type": "contain_namespace", "namespace": "lab-payments",
                                          "name": "lab-payments", "reason": "e2e containment"}, headers=H)
    aid = r.json()["id"]
    action = wait(lambda: (lambda a: a if a["status"] not in ("approved", "executing") else None)(
        c.get(f"/api/v1/responses/{aid}").json()), timeout=120, what="containment")
    check("Containment action succeeded", action["status"] == "succeeded", status=action["status"])
    time.sleep(10)
    after = probe()
    check("DNS still resolves", after.get("dns"), observed=after)
    check("Same-namespace traffic still allowed", after.get("same"), observed=after)
    check("Kubernetes API server unreachable", not after.get("api", True), observed=after)
    check("Pods in other namespaces unreachable", not after.get("cross", True), observed=after)
    r = c.post("/api/v1/responses", json={"action_type": "release_containment", "namespace": "lab-payments",
                                          "name": "lab-payments", "reason": "e2e cleanup"}, headers=H)
    rid = r.json()["id"]
    released = wait(lambda: (lambda a: a if a["status"] not in ("approved", "executing") else None)(
        c.get(f"/api/v1/responses/{rid}").json()), timeout=120, what="release containment")
    check("Containment released", released["status"] == "succeeded", status=released["status"])
    time.sleep(10)
    restored = probe()
    check("Connectivity restored after release", all(restored.values()), observed=restored)
    out["action_id"] = aid
    return out


def destructive_flow(c: httpx.Client) -> dict:
    """Delete a pod with forensics, scale a Deployment to zero, and prove the lab guard refuses other targets."""
    out: dict = {"checks": []}

    def check(title: str, passed: bool, **obs) -> None:
        out["checks"].append({"title": title, "passed": bool(passed), **obs})

    def request(action_type: str, namespace: str, name: str, reason: str) -> dict:
        r = c.post("/api/v1/responses", json={"action_type": action_type, "namespace": namespace, "name": name,
                                              "reason": reason}, headers=H)
        r.raise_for_status()
        aid = r.json()["id"]
        return wait(lambda: (lambda a: a if a["status"] not in ("approved", "executing") else None)(
            c.get(f"/api/v1/responses/{aid}").json()), timeout=120, what=action_type)

    def catalog_pods() -> list[dict]:
        items = json.loads(kubectl("-n", "lab-apps", "get", "pod", "-l", "app=catalog", "-o", "json").stdout)["items"]
        return [p for p in items if not p["metadata"].get("deletionTimestamp")]

    def audited(action_id: str) -> bool:
        return any((e.get("details") or {}).get("action_id") == action_id
                   for e in c.get("/api/v1/audit", params={"action": "response.", "limit": 200}).json())

    # Delete pod: forensics are captured first, the Deployment replaces the pod.
    victim = catalog_pods()[0]
    name, uid = victim["metadata"]["name"], victim["metadata"]["uid"]
    deleted = request("delete_pod", "lab-apps", name, "e2e: delete compromised pod")
    out["delete_action_id"] = deleted["id"]
    check("Delete pod succeeded with verified deletion", deleted["status"] == "succeeded"
          and (deleted.get("verification") or {}).get("verified"), status=deleted["status"])
    forensics = (deleted.get("result") or {}).get("forensics") or {}
    check("Forensics captured before deletion (spec, images, owner, logs)",
          forensics.get("pod_uid") == uid and forensics.get("spec") and forensics.get("images")
          and forensics.get("owner_references") and "log_tail" in forensics,
          captured=sorted(forensics))
    replacement = wait(lambda: next((p for p in catalog_pods() if p["metadata"]["uid"] != uid and any(
        cs.get("ready") for cs in p["status"].get("containerStatuses", []))), None), timeout=120,
        what="replacement pod")
    check("Deployment replaced the pod with a new ready one", replacement is not None
          and all(p["metadata"]["uid"] != uid for p in catalog_pods()),
          replacement=replacement["metadata"]["name"] if replacement else None)
    check("Delete recorded in the audit trail", audited(deleted["id"]))

    # Scale to zero: the Deployment stops running; restoring it is a deliberate manual step.
    scaled = request("scale_to_zero", "lab-apps", "catalog", "e2e: stop compromised workload")
    out["scale_action_id"] = scaled["id"]
    previous = (scaled.get("result") or {}).get("previous_replicas")
    check("Scale to zero succeeded with verified replicas == 0", scaled["status"] == "succeeded"
          and (scaled.get("verification") or {}).get("verified"), status=scaled["status"])
    check("Previous replica count recorded for restore", isinstance(previous, int) and previous > 0,
          previous_replicas=previous)
    gone = wait(lambda: True if not catalog_pods() else None, timeout=120, what="catalog pods gone")
    check("No catalog pods remain running", gone is True)
    kubectl("-n", "lab-apps", "scale", "deployment/catalog", f"--replicas={previous or 1}")
    restored = kubectl("-n", "lab-apps", "rollout", "status", "deployment/catalog", "--timeout=120s",
                       check=False, timeout=150).returncode == 0
    check("Deployment restored after manual scale-up", restored)

    # Lab guard: the same destructive action against a non-lab namespace must be refused, not executed.
    dns = kubectl("-n", "kube-system", "get", "pod", "-l", "k8s-app=kube-dns",
                  "-o", "jsonpath={.items[0].metadata.name}").stdout
    refused = request("delete_pod", "kube-system", dns, "e2e: lab guard must refuse this")
    out["refused_action_id"] = refused["id"]
    still_there = kubectl("-n", "kube-system", "get", "pod", dns, check=False).returncode == 0
    check("Action outside the lab refused by the lab guard", refused["status"] == "refused",
          status=refused["status"], error=refused.get("error"))
    check("Target outside the lab left untouched", still_there)
    return out


def write_report(results: list[dict], response: dict | None, containment: dict | None,
                 destructive: dict | None, scenarios: dict, coverage: dict, meta: dict) -> None:
    out_dir = ROOT / "docs" / "validation"
    out_dir.mkdir(parents=True, exist_ok=True)
    data = {"generated_at": datetime.now(UTC).isoformat(), "environment": meta, "results": results,
            "response_validation": response, "containment_validation": containment,
            "destructive_validation": destructive, "mitre": {k: coverage[k] for k in (
                "total_techniques", "validated", "implemented", "validated_pct", "implemented_pct")}}
    (out_dir / "detection-validation-report.json").write_text(json.dumps(data, indent=2, default=str))

    lines = [
        "# Detection Validation Report", "",
        f"Generated by `e2e/run_e2e.py` on {data['generated_at']} from live laboratory runs. "
        "Every row is the outcome recorded by the KubeShield API for a real scenario execution.", "",
        "## Environment", "",
    ]
    lines += [f"- **{k}**: {v}" for k, v in meta.items()]
    lines += ["", "## Scenario results", "",
              "| Scenario | Expected | Outcome | Checks passed | Run | Evidence |",
              "|---|---|---|---|---|---|"]
    for r in results:
        checks = r["checks"]
        ev = r["evidence"]
        evidence = ", ".join(f"`{e}`" for e in (ev.get("event_ids") or [])[:3]) or (
            f"scan `{ev['scan_id']}`" if ev.get("scan_id") else ", ".join(ev.get("findings", [])[:4]))
        lines.append(f"| {scenarios[r['scenario_id']]['title']} | {EXPECTED[r['scenario_id']]} | "
                     f"**{r['outcome']}** | {sum(c['passed'] for c in checks)}/{len(checks)} | `{r['id']}` | "
                     f"{evidence} |")
    lines += ["", "### Check details", ""]
    for r in results:
        lines.append(f"**{scenarios[r['scenario_id']]['title']}** (`{r['scenario_id']}`) — {r['outcome']}")
        lines.append("")
        for c in r["checks"]:
            lines.append(f"- {'PASS' if c['passed'] else 'FAIL'} — {c['title']}")
        if r.get("error"):
            lines.append(f"- ERROR — {r['error']}")
        lines.append("")
    if response:
        lines += ["## Response validation (detect → respond → verify)", "",
                  f"Incident `{response.get('incident_id')}`, action `{response.get('action_id')}`.", ""]
        lines += [f"- {'PASS' if c['passed'] else 'FAIL'} — {c['title']}" for c in response["checks"]]
        lines.append("")
    if containment:
        lines += ["## Namespace containment validation", "",
                  f"Action `{containment.get('action_id')}` on `lab-payments`, probed from `payments-api`.", ""]
        lines += [f"- {'PASS' if c['passed'] else 'FAIL'} — {c['title']}" for c in containment["checks"]]
        lines.append("")
    if destructive:
        lines += ["## Destructive actions and lab guard validation", "",
                  f"Delete `{destructive.get('delete_action_id')}`, scale to zero "
                  f"`{destructive.get('scale_action_id')}` on `lab-apps/catalog`; refused "
                  f"`{destructive.get('refused_action_id')}` in `kube-system`.", ""]
        lines += [f"- {'PASS' if c['passed'] else 'FAIL'} — {c['title']}" for c in destructive["checks"]]
        lines.append("")
    lines += ["## MITRE ATT&CK coverage at time of report", "",
              f"{coverage['validated']} of {coverage['total_techniques']} techniques in the KubeShield reference "
              f"set are validated by these runs ({coverage['validated_pct']}%); {coverage['implemented']} have an "
              f"implemented detection ({coverage['implemented_pct']}%). This is not a claim of full ATT&CK "
              "coverage.", ""]
    (out_dir / "detection-validation-report.md").write_text("\n".join(lines))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8080")
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--no-report", action="store_true")
    args = ap.parse_args()

    c = httpx.Client(base_url=args.url, timeout=60)
    c.post("/api/v1/auth/login", json={"username": "admin", "password": admin_password()}).raise_for_status()
    status = c.get("/api/v1/system/status").json()
    assert status["kubernetes"]["reachable"], "KubeShield cannot reach the Kubernetes API"
    integrations = {i["key"]: i["state"] for i in status["integrations"]}
    print("integrations:", integrations)

    scenarios = {s["id"]: s for s in c.get("/api/v1/simulations/scenarios").json()}
    results, failures = [], []
    for sid in args.only or EXPECTED:
        print(f"--> {sid}", flush=True)
        run = run_scenario(c, sid)
        results.append(run)
        ok = run["outcome"] == EXPECTED[sid]
        print(f"    outcome={run['outcome']} expected={EXPECTED[sid]} {'OK' if ok else 'FAIL'}")
        for chk in run["checks"]:
            print(f"      {'PASS' if chk['passed'] else 'FAIL'} {chk['title']}")
        if not ok:
            failures.append(sid)

    response = None
    token_run = next((r for r in results if r["scenario_id"] == "service-account-token-access"), None)
    if token_run and token_run["outcome"] == "detected":
        print("--> response flow (approve isolation, verify containment, release)")
        response = response_flow(c, token_run)
        for chk in response["checks"]:
            print(f"      {'PASS' if chk['passed'] else 'FAIL'} {chk['title']}")
        if not all(chk["passed"] for chk in response["checks"]):
            failures.append("response-flow")

    containment = None
    if not args.only:
        print("--> namespace containment (contain, probe, release)")
        containment = containment_flow(c)
        for chk in containment["checks"]:
            print(f"      {'PASS' if chk['passed'] else 'FAIL'} {chk['title']}")
        if not all(chk["passed"] for chk in containment["checks"]):
            failures.append("containment-flow")

    destructive = None
    if not args.only:
        print("--> destructive actions (delete pod, scale to zero, lab guard)")
        destructive = destructive_flow(c)
        for chk in destructive["checks"]:
            print(f"      {'PASS' if chk['passed'] else 'FAIL'} {chk['title']}")
        if not all(chk["passed"] for chk in destructive["checks"]):
            failures.append("destructive-flow")

    if not args.no_report:
        nodes = json.loads(kubectl("get", "nodes", "-o", "json").stdout)["items"]
        info = nodes[0]["status"]["nodeInfo"]
        meta = {"kubernetes": info["kubeletVersion"], "node_os": info["osImage"], "kernel": info["kernelVersion"],
                "container_runtime": info["containerRuntimeVersion"], "architecture": info["architecture"],
                "integrations": ", ".join(f"{k}={v}" for k, v in integrations.items()),
                "kubeshield": status["version"], "trivy": status["trivy"]["version"]}
        write_report(results, response, containment, destructive, scenarios,
                     c.get("/api/v1/mitre/coverage").json(), meta)
        print("report written to docs/validation/")
    print("FAILED:" if failures else "ALL PASSED", " ".join(failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
