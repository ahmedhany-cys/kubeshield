# Detection rules

KubeShield ships eight custom Falco rules, one Cilium/Hubble-derived detection and one Kyverno
admission detection. All are listed in the dashboard (Settings → Detection catalog) together with the
number of events received and the most recent successful validation run.

The Falco rules live in [`deploy/falco/kubeshield_rules.yaml`](../deploy/falco/kubeshield_rules.yaml) and are
loaded next to Falco's upstream stable ruleset. Falco runs with `rule_matching: all` so an event that
matches both an upstream rule and a KubeShield rule produces both alerts (Falco's default, `first`, would
silently drop the second).

## Scope

The macro `ks_workload_container` limits KubeShield rules to containers in non-platform namespaces
(`kube-system`, `falco`, `kyverno`, `kubeshield-system`, … are excluded via `ks_trusted_namespaces`).
Upstream rules keep their own scope.

## Rules

| ID | Rule | Signal (syscall level) | Severity | ATT&CK |
|---|---|---|---|---|
| ks.001 | Shell spawned in container | `execve` of a shell, not PID 1, parent is not a shell | medium | T1059.004, T1609 |
| ks.002 | Suspicious tool execution | `execve` of nc/ncat/nmap/socat/tcpdump/nsenter/kubectl/crictl… | high | T1046 |
| ks.003 | Sensitive file read | `open*` for read of `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers`, … | high | T1003.008 |
| ks.004 | Service account token read | `open*` for read of `…/secrets/kubernetes.io/serviceaccount/…token` | critical | T1528, T1552.001 |
| ks.005 | Setuid or setgid bit set | successful `chmod`/`fchmod`/`fchmodat`/`fchmodat2` with `S_ISUID`/`S_ISGID` | critical | T1548.001 |
| ks.006 | Execution from writable directory | `execve` where `proc.exepath` is under `/tmp`, `/var/tmp`, `/dev/shm` | critical | T1105 |
| ks.007 | Unexpected outbound connection | `connect` to a non-loopback address on a port outside 53/80/443/8080 | medium | T1046 |
| ks.008 | Sensitive host path access | `open*` below `/host`, `/hostfs`, `/rootfs`, `/node` or of a runtime socket | critical | T1611 |
| ks.101 | Network policy denied connection | Hubble flow `verdict=DROPPED`, `drop_reason=POLICY_DENIED` from a lab pod | medium | T1046 |
| ks.201 | Privileged workload blocked by admission policy | Kyverno admission denial for privileged / host-namespace / hostPath controls | high | T1610, T1611 |

Falco priorities map to KubeShield severities: Emergency/Alert/Critical → critical, Error → high,
Warning → medium, Notice → low, Informational/Debug → info. Incidents open at *medium* and above
(configurable).

## Engineering notes (found during validation)

These were discovered by running the rules against real syscalls in the lab, not assumed:

- **Falco 0.45 drops enter events.** `evt.dir=<` is deprecated and always true, so the rules do not use it.
- **Failed `connect()` calls have no socket tuple.** When Cilium drops a SYN, `connect` returns
  `ERESTARTSYS`/`ETIMEDOUT` and `fd.sip`/`fd.sport` are empty. ks.007 therefore matches on the syscall's
  `evt.arg.addr` argument, so blocked attempts are still reported.
- **`fchmodat` result is reported as `SUCCESS`, not `0`.** ks.005 uses `evt.rawres=0`; busybox `chmod`
  also uses `fchmodat2` on kernel ≥ 6.6.
- **Falco's default `rule_matching: first`** hid KubeShield alerts behind upstream rules for the same event.
- **kind-specific noise.** runc's bind-mount helper inside the kind node container triggered the upstream
  "Drop and execute new binary in container" rule at every pod start; an `append` override excludes only
  `proc.name=mount` with a `runc` parent. "Contact K8S API Server From Container" is likewise excluded for
  trusted platform namespaces (KubeShield, Kyverno and Falco legitimately call the API server).

## Tuning

- Allowed egress ports: macro `ks_allowed_egress`.
- Recon tool list: list `ks_recon_binaries`.
- Excluded namespaces: list `ks_trusted_namespaces`.

After editing, validate and reload:

```bash
kubectl -n falco exec ds/falco -c falco -- falco -V /etc/falco/falco_rules.yaml -V /etc/falco/rules.d/kubeshield_rules.yaml
./scripts/lab-up.sh   # re-applies the Falco release with the new rules
```

## Known blind spots

- Rules see syscalls, not intent: an authorised `kubectl exec` and an attacker's shell both trigger ks.001.
- ks.004 also fires for legitimate in-cluster clients that read their token from a workload namespace; add
  such workloads to an exception before using automatic responses.
- ks.007 is port-based; it does not inspect destinations or payloads.
- Statically linked or renamed tools evade name-based ks.002 (ks.006 still catches binaries run from `/tmp`).
