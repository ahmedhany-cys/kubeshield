"""Normalisation of raw telemetry into SecurityEvent records."""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from kubeshield import incidents, severity
from kubeshield.catalog import DETECTIONS_BY_ID, DETECTIONS_BY_SOURCE_RULE, techniques_from_tags
from kubeshield.models import SecurityEvent

log = logging.getLogger(__name__)

_PROCESS_FIELDS = {
    "proc.name": "name",
    "proc.cmdline": "cmdline",
    "proc.pid": "pid",
    "proc.exepath": "exepath",
    "proc.pname": "parent",
    "proc.pcmdline": "parent_cmdline",
    "user.name": "user",
    "user.uid": "uid",
    "proc.tty": "tty",
}
_EVIDENCE_PREFIXES = ("fd.", "evt.arg.", "evt.res", "evt.type", "container.image")
MAX_FIELD_LEN = 4096


def _parse_time(value: Any) -> datetime:
    if isinstance(value, str) and value:
        v = value.replace("Z", "+00:00")
        # Falco emits nanoseconds; Python handles at most microseconds.
        if "." in v:
            head, _, tail = v.partition(".")
            frac, sign, tz = tail[:9], "", ""
            for i, ch in enumerate(tail):
                if ch in "+-":
                    frac, sign, tz = tail[:i], ch, tail[i + 1 :]
                    break
            v = f"{head}.{frac[:6]}{sign}{tz}" if sign else f"{head}.{frac[:6]}"
        try:
            dt = datetime.fromisoformat(v)
            return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
        except ValueError:
            pass
    return datetime.now(UTC)


def _clip(value: Any) -> Any:
    if isinstance(value, str) and len(value) > MAX_FIELD_LEN:
        return value[:MAX_FIELD_LEN] + "…"
    return value


def _rule_id(tags: list[str], rule: str) -> str | None:
    for t in tags:
        if t.startswith("ks.") and t in DETECTIONS_BY_ID:
            return t
    det = DETECTIONS_BY_SOURCE_RULE.get(rule)
    return det.id if det else None


def normalize_falco(payload: dict[str, Any]) -> dict[str, Any]:
    """Convert a Falco/Falcosidekick JSON alert into SecurityEvent fields."""
    if not isinstance(payload, dict) or "rule" not in payload or "output" not in payload:
        raise ValueError("not a Falco alert")
    fields: dict[str, Any] = payload.get("output_fields") or {}
    tags = [str(t) for t in (payload.get("tags") or [])]
    rule = str(payload["rule"])[:255]
    rule_id = _rule_id(tags, rule)
    det = DETECTIONS_BY_ID.get(rule_id) if rule_id else None
    techniques = techniques_from_tags(tags) or (list(det.techniques) if det else [])

    uid = payload.get("uuid")
    if not uid:
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()
        uid = digest[:32]
    process = {v: _clip(fields[k]) for k, v in _PROCESS_FIELDS.items() if fields.get(k) not in (None, "")}
    evidence = {
        k: _clip(v)
        for k, v in fields.items()
        if any(k.startswith(p) for p in _EVIDENCE_PREFIXES) and v not in (None, "", "<NA>")
    }
    image = fields.get("container.image.repository")
    if image and fields.get("container.image.tag"):
        image = f"{image}:{fields['container.image.tag']}"
    priority = str(payload.get("priority", "Warning"))
    return {
        "id": f"falco_{uid}"[:64],
        "source": "falco",
        "rule": rule,
        "rule_id": rule_id,
        "severity": severity.from_falco(priority),
        "source_priority": priority,
        "timestamp": _parse_time(payload.get("time")),
        "namespace": fields.get("k8s.ns.name") or None,
        "pod": fields.get("k8s.pod.name") or None,
        "container": fields.get("container.name") or None,
        "container_id": fields.get("container.id") or None,
        "image": image,
        "node": payload.get("hostname"),
        "process": process,
        "message": _clip(str(payload["output"])),
        "evidence": evidence,
        "tags": tags,
        "techniques": techniques,
        "recommended_response": det.recommended_response if det else _generic_response(rule),
        "raw": payload,
    }


def _generic_response(rule: str) -> str:
    return (
        f"Review the evidence for '{rule}'. If the activity is not expected for this workload, "
        "isolate the pod with a network quarantine and investigate before deleting it."
    )


def store_event(db: Session, fields: dict[str, Any], *, correlate: bool = True) -> tuple[SecurityEvent, bool]:
    """Persist a normalised event. Returns (event, created). Idempotent on event id."""
    existing = db.get(SecurityEvent, fields["id"])
    if existing is not None:
        return existing, False
    event = SecurityEvent(**fields)
    db.add(event)
    db.flush()
    if correlate:
        incidents.correlate(db, event)
    return event, True
