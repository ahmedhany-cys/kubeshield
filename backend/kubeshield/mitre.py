"""ATT&CK coverage computed from implemented detections and recorded validation runs."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from kubeshield.catalog import DETECTIONS, TACTIC_ORDER, TECHNIQUES, TECHNIQUES_BY_ID
from kubeshield.models import SecurityEvent, SimulationRun

SUCCESS_OUTCOMES = ("detected", "blocked")


def validated_detections(db: Session) -> dict[str, dict[str, Any]]:
    """Detection id -> latest successful validation run that exercised it."""
    from kubeshield.simulation.scenarios import SCENARIOS

    out: dict[str, dict[str, Any]] = {}
    runs = db.scalars(select(SimulationRun).where(SimulationRun.outcome.in_(SUCCESS_OUTCOMES))
                      .order_by(SimulationRun.finished_at.desc()))
    for run in runs:
        sc = SCENARIOS.get(run.scenario_id)
        if not sc:
            continue
        for det_id in sc.expected_detections:
            out.setdefault(det_id, {"run_id": run.id, "scenario": sc.id,
                                    "at": run.finished_at.isoformat() if run.finished_at else None})
    return out


def coverage(db: Session) -> dict[str, Any]:
    validated = validated_detections(db)
    observed: dict[str, int] = {}
    # JSON columns cannot be grouped portably (PostgreSQL json has no equality operator).
    for techniques in db.scalars(select(SecurityEvent.techniques).order_by(SecurityEvent.timestamp.desc())
                                 .limit(50000)):
        for t in techniques or []:
            observed[t] = observed.get(t, 0) + 1

    rows = []
    for tech in TECHNIQUES:
        dets = [d for d in DETECTIONS if tech.id in d.techniques]
        val = [{"detection": d.id, **validated[d.id]} for d in dets if d.id in validated]
        status = "validated" if val else ("implemented" if dets else "not_covered")
        rows.append({
            "id": tech.id, "name": tech.name, "tactics": list(tech.tactics), "matrix": tech.matrix,
            "status": status,
            "detections": [{"id": d.id, "name": d.name, "source": d.source, "validated": d.id in validated}
                           for d in dets],
            "validations": val,
            "observed_events": observed.get(tech.id, 0),
        })
    # Techniques that only appear in upstream Falco rule tags are reported separately.
    extra = sorted(t for t in observed if t not in TECHNIQUES_BY_ID)
    total = len(rows)
    n_val = sum(1 for r in rows if r["status"] == "validated")
    n_impl = sum(1 for r in rows if r["status"] != "not_covered")
    return {
        "reference_set": "KubeShield reference set derived from the MITRE ATT&CK Containers matrix "
                         "plus related Linux techniques",
        "total_techniques": total,
        "validated": n_val,
        "implemented": n_impl,
        "validated_pct": round(100 * n_val / total, 1) if total else 0.0,
        "implemented_pct": round(100 * n_impl / total, 1) if total else 0.0,
        "tactics": list(TACTIC_ORDER),
        "techniques": rows,
        "observed_other_techniques": [{"id": t, "observed_events": observed[t]} for t in extra],
    }
