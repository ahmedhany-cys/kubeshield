# Attack simulation laboratory

The simulation engine (`backend/kubeshield/simulation/scenarios.py`) executes real attacker techniques
inside the isolated laboratory and then checks KubeShield's own database for the resulting telemetry.
A run is **detected** only when every expected detection was received from the target pod; a command
exiting successfully proves nothing on its own.

## Isolation

- Targets are lab namespaces only (`kubeshield.io/lab=true`); `exec_in_pod` calls `require_lab_namespace`
  before every command, and RBAC grants exec/create only there.
- No scenario contacts anything outside the cluster. The "outbound" scenario targets the lab's own
  `payments-db` service.
- The vulnerable image is pulled by Trivy for scanning; it is never run.
- Scenario resources (privileged pod, insecure Deployment) are labelled
  `app.kubernetes.io/managed-by=kubeshield-simulation` and removed after verification.

## Lab topology

| Namespace | Mode | Workloads | Purpose |
|---|---|---|---|
| `lab-apps` | enforce | `storefront` (victim, SA token mounted), `catalog` | Runtime scenarios; same-namespace-only ingress |
| `lab-payments` | enforce | `payments-db` (TCP 5432), `payments-api` | Protected tier; only `payments-api` may reach the DB |
| `lab-legacy` | audit | `legacy-reporting` (root, hostPath `/etc` → `/host/etc`, over-privileged Role) | Deliberately insecure posture target |

All lab images are `busybox:1.37` so the attack tooling (sh, cat, nc, chmod) is present without pulling
extra images.

## Scenarios

| # | Scenario | Target | Procedure | Expected telemetry | Expected detection | Expected response |
|---|---|---|---|---|---|---|
| 1 | Unexpected shell execution | `lab-apps/storefront` | `sh -c 'id; uname -a'` via exec | Falco execve of `/bin/sh` | ks.001 | alert-only playbook |
| 2 | Sensitive file access | `lab-apps/storefront` | `cat /etc/shadow` | Falco openat on `/etc/shadow` | ks.003 | isolation requested (approval) |
| 3 | Service account token access | `lab-apps/storefront` | `cat …/serviceaccount/token` | Falco openat on token | ks.004 | isolation + delete requested (approval) |
| 4 | Privileged container deployment | `lab-apps` (enforce) | create privileged + hostPID pod | Kyverno admission denial + Event | ks.201 | blocked at admission |
| 5 | Suspicious process execution | `lab-apps/storefront` | copy busybox to `/tmp`, run it; `chmod u+s` | Falco execve from `/tmp`, fchmodat S_ISUID | ks.006, ks.005 | isolation requested (approval) |
| 6 | Unauthorized pod communication | storefront → `lab-payments/payments-db:5432` | `nc -w 3 payments-db… 5432` | Falco execve + connect; Hubble DROPPED (POLICY_DENIED) | ks.002, ks.007, ks.101 | connection blocked by Cilium |
| 7 | Dangerous Kubernetes configuration | `lab-legacy` (audit) | Deployment with hostNetwork, hostPID, NET_ADMIN/SYS_PTRACE | posture findings + Kyverno audit PolicyReport | KS-POD-002/004/006 + 6 audit policies | findings with remediation; Deployment removed |
| 8 | Vulnerable container image | `alpine:3.10.0` | Trivy scan before deployment | Trivy report | critical/high CVEs | fail the pre-deployment gate |
| 9 | Sensitive host path access | `lab-legacy/legacy-reporting` | `cat /host/etc/os-release` | Falco openat below `/host/` | ks.008 | isolation + delete requested (approval) |

Scenario 9 is an addition beyond the eight required scenarios; it exercises the host-path rule.

## Running scenarios

- **UI:** Attack Simulation page → *Run* (responder role). Results update live and link to the
  events, incident and response actions they produced.
- **API:** `POST /api/v1/simulations/runs {"scenario_id": "..."}` then poll `GET /api/v1/simulations/runs/{id}`.
- **All scenarios + response verification:** `python3 e2e/run_e2e.py`, which writes
  [`docs/validation/detection-validation-report.md`](validation/detection-validation-report.md).

## Outcomes

| Outcome | Meaning |
|---|---|
| `detected` | Every expected detection was received from the target (or every posture/scan check passed) |
| `blocked` | The action was prevented and the prevention was recorded (admission denial + event) |
| `partial` | Some, not all, expected detections or checks |
| `missed` | None of the expected detections arrived within the timeout |
| `error` | The scenario could not run (e.g. lab workload missing); the error is stored |

## Results

Actual outcomes, checks and evidence IDs from the most recent full run are in the
[detection validation report](validation/detection-validation-report.md).
