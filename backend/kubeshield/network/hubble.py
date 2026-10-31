"""Hubble Relay client: streams real Cilium flow observations over gRPC."""

from __future__ import annotations

import hashlib
import logging
import os
import sys
import threading
import time
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, func, select

from kubeshield import ingest
from kubeshield.catalog import DETECTIONS_BY_ID
from kubeshield.config import get_settings
from kubeshield.db import session_scope
from kubeshield.models import NetworkFlow

log = logging.getLogger(__name__)

# The generated stubs use top-level package names (observer, flow, relay).
_API_DIR = os.path.join(os.path.dirname(__file__), "hubble_api")
if _API_DIR not in sys.path:
    sys.path.insert(0, _API_DIR)

import grpc  # noqa: E402
from flow import flow_pb2  # noqa: E402
from observer import observer_pb2, observer_pb2_grpc  # noqa: E402


class HubbleStatus:
    def __init__(self) -> None:
        self.connected = False
        self.last_error: str | None = None
        self.last_flow_at: datetime | None = None
        self.flows_seen = 0
        self.flows_stored = 0
        self.address: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"connected": self.connected, "address": self.address, "last_error": self.last_error,
                "last_flow_at": self.last_flow_at.isoformat() if self.last_flow_at else None,
                "flows_seen": self.flows_seen, "flows_stored": self.flows_stored}


status = HubbleStatus()
lab_namespaces: set[str] = set()


def _endpoint(ep: Any) -> tuple[str | None, str | None]:
    return (ep.namespace or None, ep.pod_name or None)


def flow_to_row(f: Any) -> dict[str, Any] | None:
    """Convert a flow.Flow message to a NetworkFlow row, or None if it is not interesting."""
    if f.Type != flow_pb2.L3_L4 or not f.HasField("IP"):
        return None
    if f.HasField("is_reply") and f.is_reply.value:
        return None
    src_ns, src_pod = _endpoint(f.source)
    dst_ns, dst_pod = _endpoint(f.destination)
    if not (src_ns in lab_namespaces or dst_ns in lab_namespaces):
        return None
    verdict = flow_pb2.Verdict.Name(f.verdict)
    proto, port, syn_only = None, None, False
    if f.l4.HasField("TCP"):
        proto, port = "TCP", f.l4.TCP.destination_port
        syn_only = f.l4.TCP.flags.SYN and not f.l4.TCP.flags.ACK
    elif f.l4.HasField("UDP"):
        proto, port = "UDP", f.l4.UDP.destination_port
    elif f.l4.HasField("ICMPv4"):
        proto = "ICMP"
    # Keep connection attempts and every drop; skip mid-stream packets.
    if verdict == "FORWARDED" and proto == "TCP" and not syn_only:
        return None
    ts = datetime.fromtimestamp(f.time.seconds + f.time.nanos / 1e9, tz=UTC)
    drop = flow_pb2.DropReason.Name(f.drop_reason_desc) if f.drop_reason_desc else None
    svc = f.destination_service.name if f.HasField("destination_service") else None
    return {
        "timestamp": ts, "verdict": verdict, "drop_reason": drop,
        "direction": flow_pb2.TrafficDirection.Name(f.traffic_direction).lower(),
        "protocol": proto, "src_namespace": src_ns, "src_pod": src_pod, "src_ip": f.IP.source,
        "dst_namespace": dst_ns, "dst_pod": dst_pod, "dst_ip": f.IP.destination, "dst_port": port,
        "dst_service": f"{f.destination_service.namespace}/{svc}" if svc else None,
        "summary": None, "node": f.node_name or None,
    }


def _drop_event(row: dict[str, Any]) -> dict[str, Any]:
    det = DETECTIONS_BY_ID["ks.101"]
    minute = row["timestamp"].strftime("%Y%m%d%H%M")
    key = f"{row['src_namespace']}|{row['src_pod']}|{row['dst_ip']}|{row['dst_port']}|{minute}"
    src = f"{row['src_namespace']}/{row['src_pod']}" if row["src_pod"] else row["src_ip"]
    dst = f"{row['dst_namespace']}/{row['dst_pod']}" if row["dst_pod"] else row["dst_ip"]
    return {
        "id": "hubble_" + hashlib.sha256(key.encode()).hexdigest()[:40],
        "source": "hubble", "rule": det.source_rule, "rule_id": det.id, "severity": det.severity,
        "source_priority": row["drop_reason"], "timestamp": row["timestamp"],
        "namespace": row["src_namespace"], "pod": row["src_pod"], "container": None, "container_id": None,
        "image": None, "node": row["node"], "process": {},
        "message": f"Cilium dropped {row['protocol']} {src} -> {dst}:{row['dst_port']} ({row['drop_reason']})",
        "evidence": {k: row[k] for k in ("src_ip", "dst_ip", "dst_port", "protocol", "drop_reason",
                                         "dst_namespace", "dst_pod", "direction")},
        "tags": ["kubeshield", det.id, "cilium", "hubble", "network"],
        "techniques": list(det.techniques), "recommended_response": det.recommended_response,
        "raw": {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in row.items()},
    }


def _store(rows: list[dict[str, Any]]) -> None:
    with session_scope() as db:
        for row in rows:
            db.add(NetworkFlow(**row))
            if row["verdict"] == "DROPPED" and row["drop_reason"] == "POLICY_DENIED" and row["src_pod"] and \
                    row["src_namespace"] in lab_namespaces:
                ingest.store_event(db, _drop_event(row))
        status.flows_stored += len(rows)


def prune(retention: int) -> None:
    with session_scope() as db:
        total = db.scalar(select(func.count(NetworkFlow.id))) or 0
        if total > retention:
            cutoff = db.scalar(select(NetworkFlow.id).order_by(NetworkFlow.id.desc()).offset(retention).limit(1))
            if cutoff:
                db.execute(delete(NetworkFlow).where(NetworkFlow.id <= cutoff))


def run_forever(stop: threading.Event) -> None:
    address = get_settings().hubble_relay_address
    if not address:
        status.last_error = "Hubble Relay address not configured"
        return
    status.address = address
    backoff = 2.0
    while not stop.is_set():
        try:
            with grpc.insecure_channel(address) as channel:
                stub = observer_pb2_grpc.ObserverStub(channel)
                stream = stub.GetFlows(observer_pb2.GetFlowsRequest(follow=True))
                status.connected, status.last_error, backoff = True, None, 2.0
                batch: list[dict[str, Any]] = []
                last_flush = time.monotonic()
                for resp in stream:
                    if stop.is_set():
                        stream.cancel()
                        break
                    if not resp.HasField("flow"):
                        continue
                    status.flows_seen += 1
                    status.last_flow_at = datetime.now(UTC)
                    row = flow_to_row(resp.flow)
                    if row:
                        batch.append(row)
                    if batch and (len(batch) >= 50 or time.monotonic() - last_flush > 2):
                        _store(batch)
                        batch, last_flush = [], time.monotonic()
        except grpc.RpcError as exc:
            status.last_error = f"{exc.code().name}: {exc.details()}"
        except Exception as exc:  # noqa: BLE001 - keep streaming after transient failures
            log.exception("hubble stream failed")
            status.last_error = str(exc)
        status.connected = False
        stop.wait(backoff)
        backoff = min(backoff * 2, 60)
