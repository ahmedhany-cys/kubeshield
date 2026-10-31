# Incident response

## Lifecycle

1. **Detect** — a normalised `SecurityEvent` arrives (Falco, Hubble, Kyverno).
2. **Correlate** — events of severity ≥ `incidents.min_severity` (default *medium*) for the same
   namespace and pod within 30 minutes join one incident. Severity is the maximum of its events;
   three or more distinct detections raise it to at least *high* (attack-chain escalation).
3. **Respond** — enabled playbooks whose rule list and minimum severity match the event create a
   `ResponseAction`. Each playbook action is created at most once per incident.
4. **Verify** — after execution the engine reads the cluster state back. The action is `succeeded`
   only if every verification check passes; otherwise it is `failed` with the observations recorded.
5. **Close** — analysts move incidents through `open → investigating → contained → resolved`
   (or `false_positive`). Successful containment actions set `contained` automatically.

Every step writes to the audit trail (`audit_log`), visible per incident and on the Response History page.

## Response actions

| Action | Effect | Destructive | Verification |
|---|---|---|---|
| `alert_only` | Records the alert, no cluster change | no | — |
| `isolate_pod` | Labels the pod `kubeshield.io/quarantine=inc-<id>` and applies a `CiliumNetworkPolicy` with `ingressDeny`/`egressDeny` for all entities (falls back to a deny-all `NetworkPolicy` without Cilium, with a recorded caveat) | no | label present; policy present and `Valid`; **CiliumEndpoint identity includes the quarantine label** (waits up to 90 s) |
| `release_isolation` | Removes the quarantine policy and label | no | policies gone |
| `delete_pod` | Captures forensics (spec, images, owners, labels, last 100 log lines) then deletes the pod (5 s grace) | **yes** | original pod gone or terminating |
| `scale_to_zero` | Scales the owning Deployment to 0 (records previous replicas) | **yes** | `spec.replicas == 0` |
| `contain_namespace` | Namespace-wide Cilium `egressDeny` to `world`, `kube-apiserver`, `host`, `remote-node` and to pods in other namespaces (kube-system DNS and in-namespace traffic still allowed; `enableDefaultDeny` is off so the deny-only policy does not cut DNS) | no | containment policy present |
| `release_containment` | Removes the namespace containment policy | no | policy gone |

### Why Cilium deny policies

Kubernetes NetworkPolicies are additive allow-lists: if any other policy allows traffic to a pod, a
"deny-all" policy for that pod does not stop it. Cilium `ingressDeny`/`egressDeny` rules take precedence
over allow rules, so the quarantine holds regardless of existing policies.

### Why enforcement is verified separately

During validation the quarantine policy existed but traffic still flowed for ~20 s: Cilium enforces a
label-based policy only after the endpoint is re-assigned a security identity that includes the new
label. KubeShield therefore polls the pod's `CiliumEndpoint` until its identity contains the quarantine
label and the policy is `Valid`. The end-to-end test then proves containment with real connections in
both directions (see [validation report](validation/detection-validation-report.md)).

### Namespace containment lessons

Two problems were found while validating containment with real traffic, and both are fixed:

1. A Cilium policy containing only deny rules still switches selected endpoints to default-deny for that
   direction, which broke DNS. The policy sets `enableDefaultDeny: {egress: false, ingress: false}`.
2. In kind the API server is reached through a host-network identity; a namespace-label `toEndpoints`
   deny does not select it, so the API server stayed reachable. The policy denies the `kube-apiserver`,
   `host` and `remote-node` entities explicitly.

The E2E harness checks DNS, same-namespace traffic, API server reachability and a cross-namespace pod
before and after containment.

## Playbooks (defaults)

| Playbook | Rules | Min severity | Action | Mode |
|---|---|---|---|---|
| Quarantine pods with credential access | ks.003, ks.004 | high | isolate_pod | approval |
| Quarantine pods with host or privilege escalation activity | ks.005, ks.006, ks.008 | critical | isolate_pod | approval |
| Delete compromised lab pod | ks.004, ks.006, ks.008 | critical | delete_pod | approval |
| Notify on interactive shells | ks.001, ks.002 | medium | alert_only | alert_only |

Admins can create, edit, disable or delete playbooks in the UI (`/api/v1/playbooks`).

## Safety controls

- **Approval by default.** All default playbooks require approval or only alert.
- **Global switches.** `response.auto_enabled` (default off) — when off, `auto` playbooks fall back to approval.
  `response.auto_destructive_enabled` (default off) — delete/scale never run automatically unless enabled.
- **Lab guard.** Every execution re-reads the target namespace and refuses (`refused`) unless it carries
  `kubeshield.io/lab=true`. RBAC independently grants write verbs only in the configured lab namespaces.
- **Role separation.** viewer: read; responder: approve/request non-destructive actions, run simulations;
  admin: destructive actions, playbooks, settings.
- **Forensics before deletion.** Pod spec and recent logs are stored in the action result.

## Example investigation

Run the *Service account token access* scenario, then open the incident:

1. Timeline shows `ks.001` (shell) and `ks.004` (token read) from the same `storefront` pod, with
   process `cat`, parent `sh`, and the token path as evidence.
2. Two actions are `pending_approval`: `isolate_pod` and `delete_pod`.
3. Approve `isolate_pod`. Within ~25 s it becomes `succeeded` with three passing checks; the incident is
   `contained`.
4. From the catalog pod, the storefront pod is unreachable; from the storefront pod, DNS and egress fail.
5. Release the isolation (or approve `delete_pod`, which stores forensics and lets the Deployment
   replace the pod with a fresh token).
