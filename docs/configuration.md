# Configuration

## Environment variables (API)

All variables use the `KUBESHIELD_` prefix. Values marked *required* have no default.

| Variable | Default | Description |
|---|---|---|
| `KUBESHIELD_JWT_SECRET` | *required* (≥32 chars) | Session signing key |
| `KUBESHIELD_INGEST_TOKEN` | *required* (≥32 chars) | Bearer token for `/api/v1/ingest/falco` |
| `KUBESHIELD_ADMIN_PASSWORD` | unset | Creates user `admin` once if no users exist |
| `KUBESHIELD_ADMIN_USERNAME` | `admin` | Bootstrap admin name |
| `KUBESHIELD_DATABASE_URL` | `postgresql+psycopg://kubeshield@localhost:5432/kubeshield` | SQLAlchemy URL; supply the password via `PGPASSWORD` |
| `KUBESHIELD_KUBE_MODE` | `in-cluster` | `in-cluster`, `kubeconfig` or `disabled` |
| `KUBESHIELD_KUBE_CONTEXT` | unset | kubeconfig context when `KUBE_MODE=kubeconfig` |
| `KUBESHIELD_LAB_LABEL` | `kubeshield.io/lab` | Namespace label (value `true`) that marks the isolated lab |
| `KUBESHIELD_PREFLIGHT_NAMESPACE` | `kubeshield-preflight` | Namespace for dry-run admission checks |
| `KUBESHIELD_HUBBLE_RELAY_ADDRESS` | `hubble-relay.kube-system.svc:80` | Empty disables flow streaming |
| `KUBESHIELD_TRIVY_BINARY` | `trivy` | Path to the Trivy binary |
| `KUBESHIELD_TRIVY_CACHE_DIR` | unset (image sets `/var/cache/trivy`) | Trivy DB cache |
| `KUBESHIELD_TRIVY_TIMEOUT_SECONDS` | `600` | Per-scan timeout |
| `KUBESHIELD_INVENTORY_INTERVAL_SECONDS` | `60` | Inventory/posture refresh |
| `KUBESHIELD_POLICY_INTERVAL_SECONDS` | `60` | Kyverno sync |
| `KUBESHIELD_INCIDENT_WINDOW_MINUTES` | `30` | Correlation window |
| `KUBESHIELD_FLOW_RETENTION` | `20000` | Stored flow rows kept |
| `KUBESHIELD_SESSION_TTL_MINUTES` | `480` | Session lifetime |
| `KUBESHIELD_COOKIE_SECURE` | `true` | Set `false` only for plain-HTTP loopback use |
| `KUBESHIELD_WORKERS_ENABLED` | `true` | Background workers |
| `KUBESHIELD_STATIC_DIR` | unset (image sets `/app/static`) | Built dashboard |

## Runtime settings (Settings page, admin only)

| Key | Default | Effect |
|---|---|---|
| `response.auto_enabled` | `false` | Allow playbooks in `auto` mode to execute without approval |
| `response.auto_destructive_enabled` | `false` | Additionally allow automatic delete/scale actions |
| `incidents.min_severity` | `medium` | Minimum event severity that opens an incident |
| `simulation.enabled` | `true` | Allow attack simulations |
| `scanner.scan_workload_images` | `true` | Scan images of running workloads (≤2 new images per cycle, re-scan after 24 h) |

Every change is written to the audit log with old and new values.

## Helm values (`deploy/helm/kubeshield/values.yaml`)

| Value | Default | Description |
|---|---|---|
| `image.repository` / `image.tag` | `kubeshield` / `0.1.0` | Image loaded into kind by `lab-up.sh` |
| `existingSecret` | `kubeshield-secrets` | Keys: `jwt-secret`, `ingest-token`, `admin-password`, `postgres-password` |
| `labNamespaces` | `[lab-apps, lab-payments, lab-legacy]` | Namespaces that receive the responder Role |
| `api.nodePort` | `30080` | Mapped to `127.0.0.1:8080` by the kind config |
| `api.cookieSecure` | `false` | Lab uses HTTP on loopback |
| `api.resources`, `postgres.resources` | see file | Requests/limits |

## Policy modes

Namespaces opt in with `kubeshield.io/policy-mode=enforce` or `=audit`. The policy chart renders each
control twice (`ks-<control>-enforce` with `validationActions: [Deny]`, `ks-<control>-audit` with
`[Audit]`); background scanning reports existing violations in both modes. Toggle controls or modes in
`deploy/helm/kubeshield-policies/values.yaml` and re-run `lab-up.sh`. KubeShield itself only reads policies.

## Adding a lab namespace

```bash
kubectl label namespace my-lab kubeshield.io/lab=true kubeshield.io/policy-mode=audit
# add it to labNamespaces in the Helm values so the responder Role is created, then:
./scripts/lab-up.sh
```
