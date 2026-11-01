# Security model

KubeShield holds powerful credentials (it can delete pods in the lab) and receives untrusted input
(alerts containing attacker-controlled command lines). It is treated as a security-sensitive application.

## Identity and access

| Control | Implementation |
|---|---|
| User authentication | Username/password; Argon2id hashes (`argon2-cffi`); constant-time path for unknown users |
| Sessions | HS256 JWT in an `HttpOnly`, `SameSite=Strict` cookie (`Secure` configurable, on by default), 8 h TTL; account re-checked on every request |
| Brute force | 5 failed logins per IP+username per 5 minutes → HTTP 429 |
| CSRF | `SameSite=Strict` plus a mandatory `X-Requested-With: kubeshield` header on every state-changing API call |
| Authorisation | Roles `viewer < responder < admin`; destructive actions, playbooks and settings require `admin` |
| Ingestion | Separate 256-bit bearer token, compared in constant time; 1 MB body limit |
| Bootstrap | Admin user created once from `KUBESHIELD_ADMIN_PASSWORD`; no default credentials exist |

## Secrets

- No credentials in the repository, images or Helm values. `scripts/lab-up.sh` generates the JWT secret,
  ingest token, admin password and database password with `openssl rand` and stores them only in the
  `kubeshield-secrets` Secret; the ingest token is copied into Falcosidekick's own Secret.
- The PostgreSQL password is passed as `PGPASSWORD`, not embedded in the connection URL.
- Trivy secret findings store the rule, title, file and line numbers only — never the matched value.
- The application refuses to start without a ≥32-character JWT secret and ingest token.

## Kubernetes permissions

The API's ServiceAccount does not have cluster-admin. Every permission and its purpose:

| Scope | Resources | Verbs | Why |
|---|---|---|---|
| Cluster (ClusterRole `kubeshield-reader`) | nodes, namespaces, pods, services, serviceaccounts; deployments, daemonsets, statefulsets, replicasets; networkpolicies; roles, rolebindings, clusterroles, clusterrolebindings; ciliumnetworkpolicies; validatingpolicies; policyreports, clusterpolicyreports | get, list, watch | Inventory, posture and RBAC analysis, integration health, Kyverno results. **Secrets and ConfigMaps are not readable.** |
| Each lab namespace (Role `kubeshield-responder`) | pods | get, list, create, patch, delete | Quarantine labels, delete-pod response, privileged-pod simulation |
| | pods/exec | create, get | Attack simulations run commands in lab pods |
| | pods/log | get | Forensics before deletion |
| | deployments, deployments/scale | get, list, create, patch, delete / get, patch, update | Scale-to-zero response, dangerous-configuration simulation |
| | networkpolicies, ciliumnetworkpolicies | get, list, create, update, delete | Quarantine and containment policies |
| | ciliumendpoints | get | Verifying quarantine enforcement |
| `kubeshield-preflight` (Role) | pods, deployments, daemonsets, statefulsets, replicasets, jobs, cronjobs | create | Pre-deployment gate. The API only sends `dryRun=All`; RBAC cannot express dry-run-only, so the namespace is dedicated, empty and default-deny. |
| `default` (Role) | events | get, list, watch | Kyverno writes admission denials as Events here |

Elevated components that are *not* KubeShield: Falco and Cilium agents run privileged (required for eBPF
and the CNI); Kyverno runs its admission webhook. Their charts are the upstream ones.

## Workload hardening

Both KubeShield pods run in an enforce-mode namespace, so they must satisfy KubeShield's own Kyverno
policies:

- `runAsNonRoot`, fixed non-root UID (10001 API, 70 PostgreSQL), `seccompProfile: RuntimeDefault`
- `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, all capabilities dropped
- CPU/memory limits; writable paths are size-limited `emptyDir` volumes
- PostgreSQL accepts connections only from the API pod (NetworkPolicy); the namespace is default-deny ingress;
  the API accepts traffic only from the `falco` namespace and the NodePort path
- Image: `python:3.13-slim` with OS packages upgraded at build time; Trivy copied from the official image

## Application security

- All inputs validated with Pydantic (Kubernetes names against DNS-1123 patterns, enums for actions,
  modes, severities and statuses, length limits everywhere).
- Image references are validated against a strict pattern and passed to Trivy as an argv list after `--`
  (no shell, no option injection).
- Manifests in the pre-deployment gate are parsed with `yaml.safe_load_all`, limited to 20 objects and
  256 KB, restricted to workload kinds, and forced into the preflight namespace.
- Security headers: CSP (`default-src 'self'`, `frame-ancestors 'none'`), `X-Frame-Options: DENY`,
  `nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` for API responses.
- Alert content is rendered as text by React (no `dangerouslySetInnerHTML`).

## Network exposure

The kind API server and the KubeShield NodePort are bound to `127.0.0.1`. Nothing listens on external
interfaces. Do not expose the lab: the UI uses plain HTTP on loopback (`cookieSecure: false` in the
lab values). Put KubeShield behind TLS and set `cookieSecure: true` anywhere else.

## Supply chain

- Python and npm dependencies are pinned through `pyproject.toml` minimums and `package-lock.json`;
  CI runs `pip-audit`, `npm audit`, Trivy config, secret and image scans.
- CI actions are pinned to commit SHAs; Trivy runs from the pinned `aquasec/trivy:0.76.1` image rather than
  a wrapper action.
- Accepted scanner findings live in `.trivyignore.yaml`, each scoped to one file with its reason. Today
  that is two HIGH RBAC findings on the lab-only responder Role: `pods/exec` (simulations) and
  NetworkPolicy write access (quarantine without Cilium). Both are the response capability itself and
  are never granted outside namespaces labelled `kubeshield.io/lab=true`.
- The runtime image contains no `pip`. One accepted image finding (with an expiry date): a go-jose DoS
  CVE inside the bundled Trivy 0.76.1 binary, the latest Trivy release at the time of writing.
- Hubble gRPC stubs are generated from Cilium v1.20.4 protos (Apache-2.0), vendored in
  `backend/proto` and `backend/kubeshield/network/hubble_api`.

## Reporting vulnerabilities

See [SECURITY.md](../SECURITY.md).
