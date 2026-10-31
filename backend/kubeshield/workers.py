"""Background workers: inventory/posture, Kyverno sync, Hubble flow stream, image scans."""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from typing import Any

from sqlalchemy import delete, select

from kubeshield import settings_store
from kubeshield.config import get_settings
from kubeshield.db import session_scope
from kubeshield.models import InventorySnapshot, utcnow

log = logging.getLogger(__name__)
_stop = threading.Event()
_threads: list[threading.Thread] = []
_status: dict[str, dict[str, Any]] = {}
SNAPSHOT_RETENTION = 200
MAX_NEW_SCANS_PER_CYCLE = 2


def worker_status() -> dict[str, dict[str, Any]]:
    return {k: dict(v) for k, v in _status.items()}


def _loop(name: str, interval: int, fn: Callable[[], Any]) -> None:
    _status[name] = {"running": True, "last_run": None, "last_error": None, "last_result": None}
    while not _stop.is_set():
        started = time.monotonic()
        try:
            _status[name]["last_result"] = fn()
            _status[name]["last_error"] = None
        except Exception as exc:  # noqa: BLE001 - workers must keep running
            log.warning("worker %s failed: %s", name, exc)
            _status[name]["last_error"] = str(exc)[:500]
        _status[name]["last_run"] = utcnow().isoformat()
        _stop.wait(max(1.0, interval - (time.monotonic() - started)))
    _status[name]["running"] = False


def inventory_cycle() -> dict[str, Any]:
    from kubeshield.k8s import inventory
    from kubeshield.network import hubble
    from kubeshield.scanners import trivy

    try:
        with session_scope() as db:
            snap = inventory.collect(db)
            data = snap.data
    except Exception as exc:
        with session_scope() as db:
            inventory.record_failure(db, str(exc))
        raise
    hubble.lab_namespaces.clear()
    hubble.lab_namespaces.update(n["name"] for n in data["namespaces"] if n["lab"])
    queued = 0
    with session_scope() as db:
        if settings_store.get(db, "scanner.scan_workload_images"):
            images: dict[str, list[str]] = {}
            for p in data["pods"]:
                if p["platform"]:
                    continue
                for img in p["images"]:
                    images.setdefault(img, []).append(f"{p['namespace']}/{p['owner'] or p['name']}")
            for image in trivy.images_due_for_scan(db, images)[:MAX_NEW_SCANS_PER_CYCLE]:
                trivy.queue_scan(db, image, "workload", "system", sorted(set(images[image])))
                queued += 1
        keep = db.scalar(select(InventorySnapshot.id).order_by(InventorySnapshot.id.desc())
                         .offset(SNAPSHOT_RETENTION).limit(1))
        if keep:
            db.execute(delete(InventorySnapshot).where(InventorySnapshot.id <= keep))
    hubble.prune(get_settings().flow_retention)
    return {"pods": data["counts"]["pods"], "scans_queued": queued}


def policy_cycle() -> dict[str, int]:
    from kubeshield.policy import kyverno

    with session_scope() as db:
        return kyverno.sync(db)


def start() -> None:
    from kubeshield.network import hubble

    s = get_settings()
    _stop.clear()
    specs = [
        ("inventory", lambda: _loop("inventory", s.inventory_interval_seconds, inventory_cycle)),
        ("kyverno", lambda: _loop("kyverno", s.policy_interval_seconds, policy_cycle)),
    ]
    if s.hubble_relay_address:
        specs.append(("hubble", lambda: hubble.run_forever(_stop)))
    for name, target in specs:
        t = threading.Thread(target=target, name=f"ks-{name}", daemon=True)
        t.start()
        _threads.append(t)


def stop() -> None:
    _stop.set()
