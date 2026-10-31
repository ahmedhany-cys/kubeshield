"""Severity normalisation shared by every telemetry source."""

from __future__ import annotations

SEVERITIES = ("critical", "high", "medium", "low", "info")
_RANK = {s: i for i, s in enumerate(reversed(SEVERITIES))}  # info=0 ... critical=4

FALCO_PRIORITY = {
    "emergency": "critical",
    "alert": "critical",
    "critical": "critical",
    "error": "high",
    "warning": "medium",
    "notice": "low",
    "informational": "info",
    "info": "info",
    "debug": "info",
}


def rank(severity: str) -> int:
    return _RANK.get(severity.lower(), 0)


def at_least(severity: str, minimum: str) -> bool:
    return rank(severity) >= rank(minimum)


def max_severity(*values: str) -> str:
    return max(values, key=rank) if values else "info"


def from_falco(priority: str) -> str:
    return FALCO_PRIORITY.get(priority.strip().lower(), "medium")


def from_trivy(value: str | None) -> str:
    v = (value or "").lower()
    return v if v in ("critical", "high", "medium", "low") else "info"
