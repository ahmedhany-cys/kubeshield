"""Persistent data model."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator

from kubeshield.db import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:20]}"


class TZDateTime(TypeDecorator):
    """Timezone-aware UTC datetime that also round-trips through SQLite."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is not None and value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16))  # viewer | responder | admin
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(TZDateTime(), default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(TZDateTime(), nullable=True)


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(24), default="open", index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    namespace: Mapped[str | None] = mapped_column(String(253), nullable=True)
    pod: Mapped[str | None] = mapped_column(String(253), nullable=True)
    workload: Mapped[str | None] = mapped_column(String(253), nullable=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    rules: Mapped[list[str]] = mapped_column(JSON, default=list)
    techniques: Mapped[list[str]] = mapped_column(JSON, default=list)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    first_seen: Mapped[datetime] = mapped_column(TZDateTime())
    last_seen: Mapped[datetime] = mapped_column(TZDateTime(), index=True)
    created_at: Mapped[datetime] = mapped_column(TZDateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(TZDateTime(), default=utcnow, onupdate=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(TZDateTime(), nullable=True)
    simulation_run_id: Mapped[str | None] = mapped_column(String(32), nullable=True)

    events: Mapped[list[SecurityEvent]] = relationship(back_populates="incident")


class SecurityEvent(Base):
    __tablename__ = "security_events"
    __table_args__ = (
        Index("ix_events_ns_pod_time", "namespace", "pod", "timestamp"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    source: Mapped[str] = mapped_column(String(24), index=True)  # falco | hubble | kyverno | kubeshield
    rule: Mapped[str] = mapped_column(String(255), index=True)
    rule_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    source_priority: Mapped[str | None] = mapped_column(String(24), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(TZDateTime(), index=True)
    ingested_at: Mapped[datetime] = mapped_column(TZDateTime(), default=utcnow)
    namespace: Mapped[str | None] = mapped_column(String(253), nullable=True)
    pod: Mapped[str | None] = mapped_column(String(253), nullable=True)
    container: Mapped[str | None] = mapped_column(String(253), nullable=True)
    container_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    image: Mapped[str | None] = mapped_column(String(512), nullable=True)
    node: Mapped[str | None] = mapped_column(String(253), nullable=True)
    process: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    message: Mapped[str] = mapped_column(Text)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    techniques: Mapped[list[str]] = mapped_column(JSON, default=list)
    recommended_response: Mapped[str] = mapped_column(Text, default="")
    raw: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id"), nullable=True, index=True)

    incident: Mapped[Incident | None] = relationship(back_populates="events")


class ResponseAction(Base):
    __tablename__ = "response_actions"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("act"))
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id"), nullable=True, index=True)
    trigger_event_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    playbook_id: Mapped[int | None] = mapped_column(ForeignKey("playbooks.id", ondelete="SET NULL"), nullable=True)
    action_type: Mapped[str] = mapped_column(String(32))
    mode: Mapped[str] = mapped_column(String(16))  # auto | approval | manual
    status: Mapped[str] = mapped_column(String(24), index=True)
    target_namespace: Mapped[str] = mapped_column(String(253))
    target_kind: Mapped[str] = mapped_column(String(32))
    target_name: Mapped[str] = mapped_column(String(253))
    reason: Mapped[str] = mapped_column(Text, default="")
    requested_by: Mapped[str] = mapped_column(String(64))
    decided_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    requested_at: Mapped[datetime] = mapped_column(TZDateTime(), default=utcnow, index=True)
    decided_at: Mapped[datetime | None] = mapped_column(TZDateTime(), nullable=True)
    executed_at: Mapped[datetime | None] = mapped_column(TZDateTime(), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(TZDateTime(), nullable=True)
    result: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    verification: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class Playbook(Base):
    __tablename__ = "playbooks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    match_rule_ids: Mapped[list[str]] = mapped_column(JSON, default=list)  # empty = any rule
    min_severity: Mapped[str] = mapped_column(String(16), default="high")
    action_type: Mapped[str] = mapped_column(String(32))
    mode: Mapped[str] = mapped_column(String(16), default="approval")  # alert_only | approval | auto
    created_at: Mapped[datetime] = mapped_column(TZDateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(TZDateTime(), default=utcnow, onupdate=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(TZDateTime(), default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64), index=True)
    target: Mapped[str | None] = mapped_column(String(512), nullable=True)
    incident_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)


class AppSetting(Base):
    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[Any] = mapped_column(JSON)
    updated_at: Mapped[datetime] = mapped_column(TZDateTime(), default=utcnow, onupdate=utcnow)
    updated_by: Mapped[str | None] = mapped_column(String(64), nullable=True)


class PostureFinding(Base):
    __tablename__ = "posture_findings"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # deterministic fingerprint
    check_id: Mapped[str] = mapped_column(String(32), index=True)
    title: Mapped[str] = mapped_column(String(255))
    category: Mapped[str] = mapped_column(String(32), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    resource_kind: Mapped[str] = mapped_column(String(64))
    namespace: Mapped[str | None] = mapped_column(String(253), nullable=True, index=True)
    resource_name: Mapped[str] = mapped_column(String(253))
    container: Mapped[str | None] = mapped_column(String(253), nullable=True)
    explanation: Mapped[str] = mapped_column(Text)
    remediation: Mapped[str] = mapped_column(Text)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)  # open | resolved
    first_seen: Mapped[datetime] = mapped_column(TZDateTime(), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(TZDateTime(), default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(TZDateTime(), nullable=True)


class InventorySnapshot(Base):
    __tablename__ = "inventory_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    taken_at: Mapped[datetime] = mapped_column(TZDateTime(), default=utcnow, index=True)
    ok: Mapped[bool] = mapped_column(Boolean)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class ImageScan(Base):
    __tablename__ = "image_scans"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("scan"))
    image: Mapped[str] = mapped_column(String(512), index=True)
    digest: Mapped[str | None] = mapped_column(String(128), nullable=True)
    status: Mapped[str] = mapped_column(String(16), index=True)  # queued | running | succeeded | failed
    trigger: Mapped[str] = mapped_column(String(32))  # workload | manual | preflight | simulation
    requested_by: Mapped[str] = mapped_column(String(64))
    started_at: Mapped[datetime] = mapped_column(TZDateTime(), default=utcnow, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(TZDateTime(), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    os_family: Mapped[str | None] = mapped_column(String(64), nullable=True)
    counts: Mapped[dict[str, int]] = mapped_column(JSON, default=dict)
    secret_count: Mapped[int] = mapped_column(Integer, default=0)
    misconfig_count: Mapped[int] = mapped_column(Integer, default=0)
    sbom_components: Mapped[int | None] = mapped_column(Integer, nullable=True)
    sbom: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    scanner_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    workloads: Mapped[list[str]] = mapped_column(JSON, default=list)

    vulnerabilities: Mapped[list[Vulnerability]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    findings: Mapped[list[ImageFinding]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("image_scans.id", ondelete="CASCADE"), index=True)
    vuln_id: Mapped[str] = mapped_column(String(64), index=True)
    pkg_name: Mapped[str] = mapped_column(String(255))
    pkg_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    installed_version: Mapped[str] = mapped_column(String(128))
    fixed_version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    title: Mapped[str | None] = mapped_column(Text, nullable=True)
    primary_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    target: Mapped[str | None] = mapped_column(String(512), nullable=True)

    scan: Mapped[ImageScan] = relationship(back_populates="vulnerabilities")


class ImageFinding(Base):
    """Secret and misconfiguration findings reported by Trivy for an image."""

    __tablename__ = "image_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("image_scans.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(16))  # secret | misconfig
    rule_id: Mapped[str] = mapped_column(String(128))
    severity: Mapped[str] = mapped_column(String(16))
    title: Mapped[str] = mapped_column(Text)
    target: Mapped[str | None] = mapped_column(String(512), nullable=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    scan: Mapped[ImageScan] = relationship(back_populates="findings")


class PolicyViolation(Base):
    """Kyverno results: background PolicyReport failures and admission denials."""

    __tablename__ = "policy_violations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # fingerprint
    source: Mapped[str] = mapped_column(String(16))  # report | admission
    policy: Mapped[str] = mapped_column(String(253), index=True)
    control: Mapped[str | None] = mapped_column(String(128), nullable=True)
    mode: Mapped[str | None] = mapped_column(String(16), nullable=True)
    severity: Mapped[str] = mapped_column(String(16))
    result: Mapped[str] = mapped_column(String(16))  # fail | warn | denied
    namespace: Mapped[str | None] = mapped_column(String(253), nullable=True, index=True)
    resource_kind: Mapped[str | None] = mapped_column(String(64), nullable=True)
    resource_name: Mapped[str | None] = mapped_column(String(253), nullable=True)
    message: Mapped[str] = mapped_column(Text)
    remediation: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    first_seen: Mapped[datetime] = mapped_column(TZDateTime(), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(TZDateTime(), default=utcnow, index=True)


class NetworkFlow(Base):
    __tablename__ = "network_flows"
    __table_args__ = (Index("ix_flows_time_verdict", "timestamp", "verdict"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(TZDateTime(), index=True)
    verdict: Mapped[str] = mapped_column(String(24))
    drop_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    direction: Mapped[str | None] = mapped_column(String(16), nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(16), nullable=True)
    src_namespace: Mapped[str | None] = mapped_column(String(253), nullable=True, index=True)
    src_pod: Mapped[str | None] = mapped_column(String(253), nullable=True)
    src_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dst_namespace: Mapped[str | None] = mapped_column(String(253), nullable=True, index=True)
    dst_pod: Mapped[str | None] = mapped_column(String(253), nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_service: Mapped[str | None] = mapped_column(String(253), nullable=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    node: Mapped[str | None] = mapped_column(String(253), nullable=True)


class SimulationRun(Base):
    __tablename__ = "simulation_runs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("sim"))
    scenario_id: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(16), index=True)  # running | completed | error
    outcome: Mapped[str | None] = mapped_column(String(24), nullable=True)  # detected | blocked | missed | ...
    requested_by: Mapped[str] = mapped_column(String(64))
    started_at: Mapped[datetime] = mapped_column(TZDateTime(), default=utcnow, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(TZDateTime(), nullable=True)
    steps: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    checks: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    incident_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
