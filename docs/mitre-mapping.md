# MITRE ATT&CK mapping

KubeShield maps each detection to ATT&CK techniques and computes coverage from **evidence**, not from
the mapping alone.

## Statuses

| Status | Meaning |
|---|---|
| **validated** | A detection mapped to the technique was observed in a recorded simulation run whose outcome was `detected` or `blocked` |
| **implemented** | A detection exists but has not been validated by a successful run yet |
| **not covered** | No KubeShield detection targets the technique |

Coverage percentages are computed over the KubeShield *reference set*: 32 techniques taken from the
ATT&CK Containers matrix plus four closely related Enterprise Linux techniques (marked `linux`). It is
a subset of ATT&CK; reaching 100 % of it would still not mean full ATT&CK coverage. Technique membership
in the Containers matrix reflects ATT&CK at the time of writing — check <https://attack.mitre.org> for
changes. Techniques found in upstream Falco rule tags that are outside the reference set are listed
separately as "observed".

## Detection → technique map

| Detection | Techniques | Validating scenario |
|---|---|---|
| ks.001 Shell spawned in container | T1059.004 Unix Shell (linux), T1609 Container Administration Command | shell-in-container |
| ks.002 Suspicious tool execution | T1046 Network Service Discovery | unauthorized-pod-communication |
| ks.003 Sensitive file read | T1003.008 /etc/passwd and /etc/shadow (linux) | sensitive-file-access |
| ks.004 Service account token read | T1528 Steal Application Access Token, T1552.001 Credentials In Files | service-account-token-access |
| ks.005 Setuid or setgid bit set | T1548.001 Setuid and Setgid (linux) | suspicious-process |
| ks.006 Execution from writable directory | T1105 Ingress Tool Transfer (linux) | suspicious-process |
| ks.007 Unexpected outbound connection | T1046 | unauthorized-pod-communication |
| ks.008 Sensitive host path access | T1611 Escape to Host | host-path-access |
| ks.101 Network policy denied connection | T1046 | unauthorized-pod-communication |
| ks.201 Privileged workload blocked | T1610 Deploy Container, T1611 | privileged-container-deployment |

Mappings are judgement calls. Examples of the reasoning:

- A shell via `kubectl exec` is T1609; a shell spawned by a compromised web process is T1059.004. The rule
  cannot distinguish them, so both are listed.
- Reading the projected service-account token is credential access to an application token (T1528) stored
  in a file (T1552.001).
- Running a binary from `/tmp` usually follows tool transfer (T1105); the rule detects the execution, not
  the transfer itself.

## Current numbers

The dashboard's MITRE page and the API (`GET /api/v1/mitre/coverage`) compute the numbers live. The
values at the time of the last validation run are recorded in the
[validation report](validation/detection-validation-report.md).

## Not covered (examples)

Persistence through implanted images (T1525), cluster-role manipulation (T1098.006), resource hijacking
(T1496), indicator removal (T1070), brute force (T1110) and orchestration jobs (T1053.007) have no
KubeShield detection. Several are good candidates for Kubernetes audit-log based detections
(see [limitations](limitations.md)).
