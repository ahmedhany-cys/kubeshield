# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |

## Reporting a vulnerability

Please report vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/ahmedhany-cys/kubeshield/security/advisories/new).
Do not open public issues for security problems.

Include the affected version or commit, reproduction steps, and the impact you observed. You should
receive an acknowledgement within 7 days.

## Scope

KubeShield is a laboratory and portfolio project. It is designed to run on a local, loopback-only
kind cluster. The attack simulation feature intentionally executes attacker techniques inside
namespaces labelled `kubeshield.io/lab=true`; reports about that intended behaviour inside the lab are
out of scope, while any way to make KubeShield act outside lab namespaces is in scope.

The threat model and every Kubernetes permission are documented in
[docs/security-model.md](docs/security-model.md).
