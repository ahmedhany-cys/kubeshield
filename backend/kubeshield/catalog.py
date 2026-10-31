"""Detection catalog and MITRE ATT&CK reference data.

The catalog describes every detection KubeShield ships. It is metadata only:
whether a detection actually works is established by recorded simulation runs
(see kubeshield.simulation), never by this file.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Detection:
    id: str
    name: str
    source: str  # falco | hubble | kyverno
    source_rule: str
    severity: str
    description: str
    techniques: tuple[str, ...]
    recommended_response: str
    scenario: str | None = None
    tags: tuple[str, ...] = field(default_factory=tuple)


DETECTIONS: tuple[Detection, ...] = (
    Detection(
        "ks.001", "Shell spawned in container", "falco", "KubeShield Shell Spawned in Container", "medium",
        "A shell started inside a workload container by something other than a shell or the entrypoint "
        "(kubectl exec sessions, web shells, RCE payloads).",
        ("T1059.004", "T1609"),
        "Confirm whether the session was an authorised kubectl exec (check API server audit logs). "
        "If not, isolate the pod with a network quarantine and capture the process tree before deleting it.",
        "shell-in-container",
    ),
    Detection(
        "ks.002", "Suspicious tool execution", "falco", "KubeShield Suspicious Tool Execution", "high",
        "Network scanners, packet capture, namespace-entry or cluster admin binaries executed in a workload.",
        ("T1046",),
        "Treat as hands-on-keyboard activity. Isolate the pod, review its egress flows in the Network page "
        "and rebuild the image without debugging tools.",
        "suspicious-process",
    ),
    Detection(
        "ks.003", "Sensitive file read", "falco", "KubeShield Sensitive File Read", "high",
        "A credential store such as /etc/shadow was opened for reading inside a container.",
        ("T1003.008",),
        "Isolate the pod, rotate any credentials baked into the image and run the workload with a read-only "
        "root filesystem as a non-root user.",
        "sensitive-file-access",
    ),
    Detection(
        "ks.004", "Service account token read", "falco", "KubeShield Service Account Token Read", "critical",
        "The projected Kubernetes service account token was read by an unexpected process.",
        ("T1528", "T1552.001"),
        "Assume the token is compromised: isolate the pod, delete it so the projected token is invalidated, "
        "review RBAC for the service account and set automountServiceAccountToken: false where unused.",
        "service-account-token-access",
    ),
    Detection(
        "ks.005", "Setuid or setgid bit set", "falco", "KubeShield Setuid or Setgid Bit Set", "critical",
        "A file was given the setuid/setgid bit inside a container, a common privilege escalation backdoor.",
        ("T1548.001",),
        "Isolate and delete the pod. Enforce allowPrivilegeEscalation: false and runAsNonRoot so setuid "
        "binaries cannot raise privileges.",
        "privilege-escalation-setuid",
    ),
    Detection(
        "ks.006", "Execution from writable directory", "falco", "KubeShield Execution From Writable Directory",
        "critical",
        "A binary executed from /tmp, /var/tmp or /dev/shm, where dropped payloads are usually staged.",
        ("T1105",),
        "Isolate the pod and preserve the dropped binary for analysis. Mount writable paths noexec or use "
        "readOnlyRootFilesystem.",
        "writable-dir-execution",
    ),
    Detection(
        "ks.007", "Unexpected outbound connection", "falco", "KubeShield Unexpected Outbound Connection",
        "medium",
        "A workload attempted a connection on a port outside the allowed egress list "
        "(reported even when a network policy blocks it).",
        ("T1046",),
        "Correlate with Hubble flows for the same pod. If the destination is not a known dependency, "
        "quarantine the pod and tighten its egress NetworkPolicy.",
        "unauthorized-pod-communication",
    ),
    Detection(
        "ks.008", "Sensitive host path access", "falco", "KubeShield Sensitive Host Path Access", "critical",
        "A file below a host filesystem mount or a container runtime socket was opened from a pod.",
        ("T1611",),
        "Delete the pod, remove hostPath mounts from the workload and enforce the disallow-host-path policy "
        "in the namespace.",
        "host-path-access",
    ),
    Detection(
        "ks.101", "Network policy denied connection", "hubble", "Cilium policy verdict DROPPED", "medium",
        "Cilium dropped a workload connection because of a network policy (observed by Hubble).",
        ("T1046",),
        "Identify the source pod and process (Falco ks.007 / ks.002 events) and decide whether the attempt "
        "was malicious or a missing allow rule.",
        "unauthorized-pod-communication",
    ),
    Detection(
        "ks.201", "Privileged workload blocked by admission policy", "kyverno",
        "ks-disallow-privileged-enforce", "high",
        "Kyverno rejected a pod that requested privileged mode or host namespaces.",
        ("T1610", "T1611"),
        "Identify who submitted the workload from the API server audit log and review their RBAC.",
        "privileged-container-deployment",
    ),
)

DETECTIONS_BY_ID = {d.id: d for d in DETECTIONS}
DETECTIONS_BY_SOURCE_RULE = {d.source_rule: d for d in DETECTIONS}


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactics: tuple[str, ...]
    # "containers": listed in the ATT&CK Containers matrix.
    # "linux": Enterprise Linux technique commonly observed inside containers.
    matrix: str


TECHNIQUES: tuple[Technique, ...] = (
    Technique("T1190", "Exploit Public-Facing Application", ("initial-access",), "containers"),
    Technique("T1133", "External Remote Services", ("initial-access", "persistence"), "containers"),
    Technique("T1078", "Valid Accounts", ("initial-access", "persistence", "privilege-escalation",
                                          "defense-evasion"), "containers"),
    Technique("T1609", "Container Administration Command", ("execution",), "containers"),
    Technique("T1610", "Deploy Container", ("execution", "defense-evasion"), "containers"),
    Technique("T1053.007", "Scheduled Task/Job: Container Orchestration Job",
              ("execution", "persistence", "privilege-escalation"), "containers"),
    Technique("T1204.003", "User Execution: Malicious Image", ("execution",), "containers"),
    Technique("T1059.004", "Command and Scripting Interpreter: Unix Shell", ("execution",), "linux"),
    Technique("T1525", "Implant Internal Image", ("persistence",), "containers"),
    Technique("T1098.006", "Account Manipulation: Additional Container Cluster Roles",
              ("persistence", "privilege-escalation"), "containers"),
    Technique("T1543.005", "Create or Modify System Process: Container Service",
              ("persistence", "privilege-escalation"), "containers"),
    Technique("T1611", "Escape to Host", ("privilege-escalation",), "containers"),
    Technique("T1068", "Exploitation for Privilege Escalation", ("privilege-escalation",), "containers"),
    Technique("T1548.001", "Abuse Elevation Control Mechanism: Setuid and Setgid",
              ("privilege-escalation", "defense-evasion"), "linux"),
    Technique("T1612", "Build Image on Host", ("defense-evasion",), "containers"),
    Technique("T1562.001", "Impair Defenses: Disable or Modify Tools", ("defense-evasion",), "containers"),
    Technique("T1070", "Indicator Removal", ("defense-evasion",), "containers"),
    Technique("T1036.005", "Masquerading: Match Legitimate Name or Location", ("defense-evasion",),
              "containers"),
    Technique("T1550.001", "Use Alternate Authentication Material: Application Access Token",
              ("defense-evasion", "lateral-movement"), "containers"),
    Technique("T1110", "Brute Force", ("credential-access",), "containers"),
    Technique("T1528", "Steal Application Access Token", ("credential-access",), "containers"),
    Technique("T1552.001", "Unsecured Credentials: Credentials In Files", ("credential-access",), "containers"),
    Technique("T1552.007", "Unsecured Credentials: Container API", ("credential-access",), "containers"),
    Technique("T1003.008", "OS Credential Dumping: /etc/passwd and /etc/shadow", ("credential-access",),
              "linux"),
    Technique("T1613", "Container and Resource Discovery", ("discovery",), "containers"),
    Technique("T1046", "Network Service Discovery", ("discovery",), "containers"),
    Technique("T1069", "Permission Groups Discovery", ("discovery",), "containers"),
    Technique("T1105", "Ingress Tool Transfer", ("command-and-control",), "linux"),
    Technique("T1485", "Data Destruction", ("impact",), "containers"),
    Technique("T1496", "Resource Hijacking", ("impact",), "containers"),
    Technique("T1498", "Network Denial of Service", ("impact",), "containers"),
    Technique("T1499", "Endpoint Denial of Service", ("impact",), "containers"),
)

TECHNIQUES_BY_ID = {t.id: t for t in TECHNIQUES}

TACTIC_ORDER = (
    "initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion",
    "credential-access", "discovery", "lateral-movement", "command-and-control", "impact",
)


def techniques_from_tags(tags: list[str] | tuple[str, ...]) -> list[str]:
    """Extract ATT&CK technique ids (T1234 / T1234.001) from rule tags."""
    out: list[str] = []
    for tag in tags:
        t = tag.strip().upper()
        if len(t) >= 5 and t[0] == "T" and t[1:5].isdigit() and (len(t) == 5 or (t[5] == "." and t[6:].isdigit())):
            if t not in out:
                out.append(t)
    return out
