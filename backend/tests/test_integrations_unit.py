"""Unit tests for Kyverno event parsing, Hubble flow conversion and ATT&CK coverage."""

import os
import sys

from kubeshield.network import hubble
from kubeshield.policy.kyverno import DENIAL_RE

sys.path.insert(0, os.path.join(os.path.dirname(hubble.__file__), "hubble_api"))
from flow import flow_pb2  # noqa: E402


def test_kyverno_denial_message_parsing():
    m = DENIAL_RE.match("Pod lab-apps/sim-privileged-abc123: fail (blocked); Privileged containers are not allowed.")
    assert m and m["kind"] == "Pod" and m["ns"] == "lab-apps" and m["name"] == "sim-privileged-abc123"
    assert m["msg"].startswith("Privileged")
    assert DENIAL_RE.match("Pod lab-apps/x: fail; scanned") is None


def _flow(verdict, syn=True, ack=False, src_ns="lab-apps", dst_ns="lab-payments", reply=False):
    f = flow_pb2.Flow(verdict=verdict, Type=flow_pb2.L3_L4, node_name="node-1")
    f.time.seconds = 1793471000
    f.IP.source, f.IP.destination = "10.244.0.10", "10.244.0.20"
    f.l4.TCP.destination_port = 5432
    f.l4.TCP.flags.SYN, f.l4.TCP.flags.ACK = syn, ack
    f.source.namespace, f.source.pod_name = src_ns, "storefront-1"
    f.destination.namespace, f.destination.pod_name = dst_ns, "payments-db-1"
    if verdict == flow_pb2.DROPPED:
        f.drop_reason_desc = flow_pb2.POLICY_DENIED
    f.is_reply.value = reply
    return f


def test_hubble_flow_conversion_and_filtering():
    hubble.lab_namespaces.clear()
    hubble.lab_namespaces.update({"lab-apps", "lab-payments"})
    row = hubble.flow_to_row(_flow(flow_pb2.DROPPED))
    assert row["verdict"] == "DROPPED" and row["drop_reason"] == "POLICY_DENIED"
    assert row["dst_port"] == 5432 and row["protocol"] == "TCP" and row["src_pod"] == "storefront-1"
    assert hubble.flow_to_row(_flow(flow_pb2.FORWARDED, syn=True, ack=True)) is None  # mid-stream
    assert hubble.flow_to_row(_flow(flow_pb2.FORWARDED, reply=True)) is None
    assert hubble.flow_to_row(_flow(flow_pb2.FORWARDED, src_ns="kube-system", dst_ns="kube-system")) is None
    ev = hubble._drop_event(row)
    assert ev["rule_id"] == "ks.101" and ev["namespace"] == "lab-apps" and "5432" in ev["message"]
    assert ev["id"] == hubble._drop_event(row)["id"]  # deduplicated per minute


def test_mitre_coverage_counts_only_validated_runs(db):
    from kubeshield import mitre
    from kubeshield.models import SimulationRun, utcnow

    cov = mitre.coverage(db)
    assert cov["validated"] == 0 and cov["implemented"] > 0
    t1528 = next(t for t in cov["techniques"] if t["id"] == "T1528")
    assert t1528["status"] == "implemented"
    db.add(SimulationRun(scenario_id="service-account-token-access", status="completed", outcome="missed",
                         requested_by="t", finished_at=utcnow()))
    db.flush()
    assert mitre.coverage(db)["validated"] == 0
    db.add(SimulationRun(scenario_id="service-account-token-access", status="completed", outcome="detected",
                         requested_by="t", finished_at=utcnow()))
    db.flush()
    cov = mitre.coverage(db)
    statuses = {t["id"]: t["status"] for t in cov["techniques"]}
    assert statuses["T1528"] == "validated" and statuses["T1552.001"] == "validated"
    assert statuses["T1611"] == "implemented" and statuses["T1496"] == "not_covered"
    assert 0 < cov["validated_pct"] < 100
