"""Runtime settings editable from the UI (persisted in the database)."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from kubeshield.models import AppSetting

DEFAULTS: dict[str, Any] = {
    # Global switch for automatic responses. When False, playbooks in "auto"
    # mode fall back to requiring approval.
    "response.auto_enabled": False,
    # Destructive actions (delete pod, scale to zero) never run automatically
    # unless this is also enabled.
    "response.auto_destructive_enabled": False,
    # Minimum severity that opens an incident.
    "incidents.min_severity": "medium",
    "simulation.enabled": True,
    "scanner.scan_workload_images": True,
}

TYPES: dict[str, type] = {k: type(v) for k, v in DEFAULTS.items()}


def get(db: Session, key: str) -> Any:
    row = db.get(AppSetting, key)
    return DEFAULTS[key] if row is None else row.value


def get_all(db: Session) -> dict[str, Any]:
    values = dict(DEFAULTS)
    for row in db.query(AppSetting).all():
        if row.key in values:
            values[row.key] = row.value
    return values


def set_value(db: Session, key: str, value: Any, actor: str) -> None:
    if key not in DEFAULTS:
        raise KeyError(key)
    if not isinstance(value, TYPES[key]):
        raise TypeError(f"{key} expects {TYPES[key].__name__}")
    row = db.get(AppSetting, key)
    if row is None:
        db.add(AppSetting(key=key, value=value, updated_by=actor))
    else:
        row.value = value
        row.updated_by = actor
    db.flush()
