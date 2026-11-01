# Troubleshooting

## Cluster / VM

**API server timeouts, `etcd failed`, `input/output error` from `docker exec`.**
The host disk filled up. On an 8 GB Mac a 6 GB Colima VM pushed macOS into ~7 GB of swap, and the swap
files exhausted the disk. Check `df -h ~` and `sysctl vm.swapusage`; restart the VM smaller
(`colima stop && colima start --cpu 4 --memory 3.5`). A Helm release interrupted by such an outage can be
stuck in `pending-upgrade`: `helm rollback <release> <last-good-revision> -n <ns>` and re-run `lab-up.sh`.

**Port 8080 already in use.** Change `hostPort` in `deploy/kind/cluster.yaml` before creating the cluster.

## Falco

**No events in Runtime Threats.**
1. `kubectl -n falco logs ds/falco -c falco | grep -i error` — rule load errors are printed at startup.
2. `kubectl -n falco logs deploy/falco-falcosidekick` — look for `Webhook - POST OK` or HTTP 401
   (token mismatch: re-run `lab-up.sh`, which re-syncs the Falcosidekick Secret and restarts it).
3. Settings → System status shows the time of the last ingested Falco event.

**A KubeShield rule never fires although the upstream rule does.** Falco's default
`rule_matching: first` stops at the first matching rule. The lab sets `rule_matching: all`.

**Driver fails to load.** The modern eBPF probe needs BTF (`/sys/kernel/btf/vmlinux`) and kernel ≥ 5.8.

## Network

**Hubble shows "disconnected".** `kubectl -n kube-system get pods -l k8s-app=hubble-relay`; when running
the API outside the cluster, port-forward the relay (`kubectl -n kube-system port-forward svc/hubble-relay 4245:80`).

**Isolation action `failed` with "Cilium endpoint re-identified … passed: false".** Cilium did not assign
the pod a new identity within 90 s. Check `kubectl -n <ns> get ciliumendpoint <pod> -o yaml` and the agent
log (`cilium-dbg endpoint list` in the cilium pod). On a heavily loaded node identity allocation can lag;
re-run the action once the node is healthy.

## Kyverno

**Lab pods rejected.** Pods in `enforce` namespaces must satisfy every control: non-root, no privilege
escalation, CPU/memory limits, pinned tags, no host namespaces/paths, no dangerous capabilities.
The rejection message names each failed policy.

**No admission denials in KubeShield.** Kyverno writes them as `PolicyViolation` Events in the `default`
namespace; KubeShield reads that namespace (Role `kubeshield-kyverno-events`).

## Trivy

**Scans stay `queued`/`running`.** The first scan downloads the vulnerability DB into the pod's
`emptyDir` (needs internet access and a few minutes); scans run one at a time.

**Scan `failed` with a registry error.** Trivy pulls the image from its registry; images that exist only
inside kind (loaded with `kind load`) cannot be scanned remotely.

**API pod evicted with `Usage of EmptyDir volume "tmp" exceeds the limit`.** Trivy stages the compressed
DB download in `/tmp` (~270 MB with Trivy 0.76) and the extracted DB takes ~1.6 GB of the cache volume.
The chart defaults (`api.tmpSizeLimit: 1Gi`, `api.trivyCacheSizeLimit: 3Gi`) cover this; earlier
defaults (256 Mi / 2 Gi) got the pod evicted on its first scan after a restart.

## Simulations

**`error: no ready, unquarantined pod with app=storefront`.** A previous response deleted or quarantined
the pod. Wait for the Deployment to recreate it, or release the quarantine.

**`missed` outcome.** Check Falco and Falcosidekick health first; the run's checks list exactly which
detection did not arrive.

**Run or scan marked `interrupted by an API restart`.** Work runs in background threads of the API pod;
if the pod restarts, the next startup marks whatever was in flight as failed (and audits it) so it does
not block new runs. Response actions caught this way are never re-executed: request them again.
