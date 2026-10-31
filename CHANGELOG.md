# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-31

### Added
- Reproducible kind laboratory: Cilium 1.20.4 with Hubble Relay, Falco 0.45.2 with Falcosidekick,
  Kyverno 1.19.2, lab namespaces and workloads, `scripts/lab-up.sh` / `lab-down.sh`.
- Eight KubeShield Falco rules (shell, suspicious tools, sensitive files, service account tokens,
  setuid planting, execution from writable paths, unexpected egress, host path access).
- Kyverno `ValidatingPolicy` guardrails in enforce and audit modes (privileged, run-as-root, host PID/IPC,
  host network, resource limits, latest tag, dangerous capabilities, hostPath, privilege escalation).
- FastAPI backend with PostgreSQL: Falco ingestion, Hubble gRPC flow streaming, Kyverno report and
  admission-denial sync, cluster inventory and posture checks (pods, controllers, RBAC, network isolation),
  Trivy image/secret/misconfiguration scanning with SBOM summaries, pre-deployment gate (server-side
  dry-run + Trivy config).
- Incident correlation and an approval-gated response engine (alert, isolate with Cilium deny policies,
  release, delete with forensics, scale to zero, namespace containment) with datapath-verified outcomes
  and a full audit trail.
- Attack simulation engine with nine scenarios verified against received telemetry.
- MITRE ATT&CK coverage computed from validation runs.
- React/TypeScript dashboard with eleven pages.
- Unit tests, end-to-end harness with generated validation report, GitHub Actions CI.
