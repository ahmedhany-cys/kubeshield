# Known limitations

This is a laboratory platform. It is not production-ready and makes no such claim.

## Scope and environment

- Validated on a single-node kind cluster (Kubernetes 1.37, Cilium 1.20.4, Falco 0.45.2, Kyverno 1.19.2)
  inside a Colima VM on macOS arm64. Multi-node clusters, other CNIs and managed Kubernetes are untested.
- Single API replica. Background workers run in-process; running several replicas would duplicate work.
- Schema is created with SQLAlchemy `create_all`; there are no migrations yet.
- The UI is served over HTTP on loopback in the lab. TLS termination is left to the deployer.

## Detection

- Eight custom Falco rules plus upstream rules, one Hubble-derived and one Kyverno-derived detection. They
  detect specific behaviours, not attackers in general. See blind spots in
  [detection-rules.md](detection-rules.md).
- No Kubernetes API audit-log ingestion, so API-level attacks (RBAC changes, secret reads through the API,
  exec authorisations) are not detected. Kind supports audit logging; this is the most valuable next source.
- Hubble flows are filtered to lab namespaces and to connection attempts/drops to keep storage bounded
  (`KUBESHIELD_FLOW_RETENTION`). L7 visibility is not enabled.
- Correlation is per namespace + pod in a time window; there is no cross-pod or graph-based correlation.

## Tetragon

Tetragon is **not integrated**, and nothing in KubeShield depends on it. While building the lab on an
8 GB host, a 6 GB VM caused host swap to exhaust the disk and corrupt etcd writes, so the VM was reduced to
3.5 GB and a third eBPF agent (after Falco and Cilium) was deliberately left out. Tetragon was not
installed or measured in this environment. Falco already covers process, file and network syscall
detection and Cilium provides the eBPF network datapath; Tetragon would mainly add in-kernel enforcement
(for example `SIGKILL` on a TracingPolicy match). The integrations panel reports Tetragon as
`not_installed` rather than hiding it.

## Response

- Quarantine via Cilium takes effect only after identity re-allocation (~20–25 s observed); verification
  waits for it, but the pod is not contained during that window.
- `delete_pod` relies on the controller to replace the pod; forensics are limited to spec, labels and the last
  100 log lines (no memory or filesystem capture).
- `scale_to_zero` supports Deployments only.
- Without Cilium, isolation falls back to a Kubernetes NetworkPolicy, which other allow policies can override
  (recorded as a caveat in the action result).

## Vulnerability management

- Trivy scans need registry and internet access for the vulnerability DB. Images only present in the kind
  node cannot be scanned.
- One scan at a time; SBOMs are summarised (first 2,000 components) rather than stored in full.

## Policy

- Policy mode is per namespace via labels; switching a namespace's mode is a label change, and editing
  policies requires a Helm upgrade (KubeShield has read-only access to policies by design).
- The pre-deployment gate requires `create` RBAC in a dedicated namespace because RBAC cannot express
  "dry-run only".

## ATT&CK

- Coverage is computed over a 32-technique reference set, not the full matrix. Mappings are documented
  judgement calls.
