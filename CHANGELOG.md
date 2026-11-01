# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- End-to-end checks for delete pod (forensics, replacement), scale to zero (restore) and the lab guard
  refusing an action outside the laboratory.

### Changed
- CI actions are pinned to commit SHAs and Trivy runs from the pinned `aquasec/trivy:0.76.1` image.
- The runtime image no longer contains `pip` (its vendored urllib3, msgpack and setuptools carried HIGH
  CVEs). Accepted scanner findings are recorded with reasons in `.trivyignore.yaml`.

### Fixed
- API pod was evicted on its first image scan after a restart: Trivy's DB download overflowed the
  256 Mi `/tmp` volume. `/tmp` and the Trivy cache limits are now configurable (`api.tmpSizeLimit`,
  `api.trivyCacheSizeLimit`) with defaults of 1 Gi and 3 Gi.
- A simulation, image scan or response action in flight when the API restarted stayed `running` forever,
  blocking every later simulation and rescans of that image. Startup now marks such work as failed and
  audits it; response actions are never replayed automatically.

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
