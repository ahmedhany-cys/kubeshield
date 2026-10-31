"""Trivy integration: image vulnerability, secret and misconfiguration scanning, SBOMs."""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess  # noqa: S404 - Trivy is invoked without a shell, with validated arguments
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from kubeshield import severity
from kubeshield.config import get_settings
from kubeshield.db import after_commit, session_scope
from kubeshield.models import ImageFinding, ImageScan, Vulnerability, utcnow

log = logging.getLogger(__name__)

# registry/repo[:tag][@sha256:digest] - deliberately strict, no whitespace or option-like prefixes.
IMAGE_RE = re.compile(r"^[a-z0-9][a-z0-9._\-/:]{0,254}(@sha256:[a-f0-9]{64})?$")
_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ks-trivy")
_lock = threading.Lock()
SYNCHRONOUS = False


class TrivyError(RuntimeError):
    pass


def validate_image(image: str) -> str:
    image = image.strip()
    if not IMAGE_RE.match(image) or ".." in image or image.startswith("-"):
        raise ValueError("invalid image reference")
    return image


def available() -> tuple[bool, str | None]:
    binary = shutil.which(get_settings().trivy_binary)
    if not binary:
        return False, None
    try:
        out = _run([binary, "--version", "--format", "json"], timeout=30)
        return True, json.loads(out).get("Version")
    except (TrivyError, json.JSONDecodeError):
        return False, None


def _env_args() -> list[str]:
    s = get_settings()
    return ["--cache-dir", s.trivy_cache_dir] if s.trivy_cache_dir else []


def _run(args: list[str], timeout: int | None = None) -> str:
    try:
        proc = subprocess.run(  # noqa: S603 - argv list, no shell
            args, capture_output=True, text=True, timeout=timeout or get_settings().trivy_timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TrivyError(f"trivy timed out after {exc.timeout}s") from exc
    except FileNotFoundError as exc:
        raise TrivyError("trivy binary not found") from exc
    if proc.returncode != 0:
        raise TrivyError((proc.stderr or proc.stdout or "trivy failed").strip()[-2000:])
    return proc.stdout


def _cvss(v: dict[str, Any]) -> float | None:
    scores = []
    for vendor in ("nvd", "redhat", "ghsa"):
        entry = (v.get("CVSS") or {}).get(vendor) or {}
        for key in ("V3Score", "V40Score", "V2Score"):
            if isinstance(entry.get(key), int | float):
                scores.append(float(entry[key]))
                break
    return scores[0] if scores else None


def parse_report(report: dict[str, Any]) -> dict[str, Any]:
    """Turn `trivy image --format json` output into rows. Secret values are never retained."""
    vulns: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for result in report.get("Results") or []:
        target = result.get("Target")
        for v in result.get("Vulnerabilities") or []:
            key = (v.get("VulnerabilityID", ""), v.get("PkgName", ""), v.get("InstalledVersion", ""))
            if key in seen:
                continue
            seen.add(key)
            vulns.append({
                "vuln_id": key[0], "pkg_name": key[1], "installed_version": key[2],
                "pkg_type": result.get("Type"), "fixed_version": v.get("FixedVersion") or None,
                "severity": severity.from_trivy(v.get("Severity")), "cvss_score": _cvss(v),
                "title": (v.get("Title") or v.get("Description") or "")[:500] or None,
                "primary_url": v.get("PrimaryURL"), "target": target,
            })
        for s in result.get("Secrets") or []:
            findings.append({
                "kind": "secret", "rule_id": s.get("RuleID", "unknown"), "severity": severity.from_trivy(
                    s.get("Severity")), "title": s.get("Title") or s.get("RuleID", "secret"), "target": target,
                "details": {"category": s.get("Category"), "start_line": s.get("StartLine"),
                            "end_line": s.get("EndLine")},
            })
        for m in result.get("Misconfigurations") or []:
            if m.get("Status") != "FAIL":
                continue
            findings.append({
                "kind": "misconfig", "rule_id": m.get("AVDID") or m.get("ID", "unknown"),
                "severity": severity.from_trivy(m.get("Severity")), "title": m.get("Title", ""),
                "target": target,
                "details": {"message": m.get("Message"), "resolution": m.get("Resolution"),
                            "url": m.get("PrimaryURL")},
            })
    counts = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
    for v in vulns:
        counts[v["severity"]] += 1
    meta = report.get("Metadata") or {}
    os_meta = meta.get("OS") or {}
    digests = meta.get("RepoDigests") or []
    return {
        "vulnerabilities": vulns, "findings": findings, "counts": counts,
        "os_family": f"{os_meta.get('Family', '')} {os_meta.get('Name', '')}".strip() or None,
        "digest": digests[0].split("@", 1)[1] if digests and "@" in digests[0] else None,
    }


def summarize_sbom(sbom: dict[str, Any], limit: int = 2000) -> dict[str, Any]:
    components = sbom.get("components") or []
    return {
        "format": f"CycloneDX {sbom.get('specVersion', '')}".strip(),
        "component_count": len(components),
        "components": [
            {"name": c.get("name"), "version": c.get("version"), "type": c.get("type"), "purl": c.get("purl")}
            for c in components[:limit]
        ],
        "truncated": len(components) > limit,
    }


def queue_scan(db: Session, image: str, trigger: str, actor: str, workloads: list[str] | None = None) -> ImageScan:
    image = validate_image(image)
    with _lock:
        running = db.scalar(select(ImageScan).where(ImageScan.image == image,
                                                    ImageScan.status.in_(("queued", "running"))))
        if running is not None:
            return running
        scan = ImageScan(image=image, status="queued", trigger=trigger, requested_by=actor,
                         workloads=workloads or [])
        db.add(scan)
        db.flush()
    after_commit(db, lambda sid=scan.id: run_scan(sid) if SYNCHRONOUS else _executor.submit(run_scan, sid))
    return scan


def run_scan(scan_id: str) -> None:
    binary = shutil.which(get_settings().trivy_binary) or get_settings().trivy_binary
    with session_scope() as db:
        scan = db.get(ImageScan, scan_id)
        if scan is None:
            return
        scan.status, scan.started_at = "running", utcnow()
        image = scan.image
    try:
        raw = _run([binary, "image", "--format", "json", "--quiet", "--scanners", "vuln,secret",
                    "--image-config-scanners", "misconfig,secret", *_env_args(), "--", image])
        parsed = parse_report(json.loads(raw))
        sbom = None
        try:
            sbom = summarize_sbom(json.loads(_run([binary, "image", "--format", "cyclonedx", "--quiet",
                                                   *_env_args(), "--", image])))
        except (TrivyError, json.JSONDecodeError) as exc:
            log.warning("SBOM generation failed for %s: %s", image, exc)
        ok, version = available()
        with session_scope() as db:
            scan = db.get(ImageScan, scan_id)
            assert scan is not None
            scan.vulnerabilities = [Vulnerability(**v) for v in parsed["vulnerabilities"]]
            scan.findings = [ImageFinding(**f) for f in parsed["findings"]]
            scan.counts = parsed["counts"]
            scan.os_family, scan.digest = parsed["os_family"], parsed["digest"]
            scan.secret_count = sum(1 for f in parsed["findings"] if f["kind"] == "secret")
            scan.misconfig_count = sum(1 for f in parsed["findings"] if f["kind"] == "misconfig")
            scan.sbom = sbom
            scan.sbom_components = sbom["component_count"] if sbom else None
            scan.scanner_version = version if ok else None
            scan.status, scan.finished_at = "succeeded", utcnow()
    except Exception as exc:  # noqa: BLE001 - record every failure on the scan row
        log.warning("scan %s failed: %s", scan_id, exc)
        with session_scope() as db:
            scan = db.get(ImageScan, scan_id)
            if scan is not None:
                scan.status, scan.error, scan.finished_at = "failed", str(exc)[:2000], utcnow()


def scan_manifest(manifest_yaml: str) -> dict[str, Any]:
    """Run `trivy config` against a manifest supplied for pre-deployment checks."""
    binary = shutil.which(get_settings().trivy_binary) or get_settings().trivy_binary
    with tempfile.TemporaryDirectory(prefix="ks-preflight-") as tmp:
        path = Path(tmp) / "manifest.yaml"
        path.write_text(manifest_yaml)
        raw = _run([binary, "config", "--format", "json", "--quiet", *_env_args(), tmp], timeout=180)
    report = json.loads(raw)
    findings = []
    for result in report.get("Results") or []:
        for m in result.get("Misconfigurations") or []:
            if m.get("Status") == "FAIL":
                findings.append({"id": m.get("AVDID") or m.get("ID"), "title": m.get("Title"),
                                 "severity": severity.from_trivy(m.get("Severity")), "message": m.get("Message"),
                                 "resolution": m.get("Resolution")})
    return {"findings": findings}


def images_due_for_scan(db: Session, images: dict[str, list[str]], max_age_hours: int = 24) -> list[str]:
    cutoff = utcnow() - timedelta(hours=max_age_hours)
    due = []
    for image in images:
        try:
            validate_image(image)
        except ValueError:
            continue
        last = db.scalar(select(ImageScan).where(ImageScan.image == image).order_by(
            ImageScan.started_at.desc()).limit(1))
        if last is None or (last.status in ("succeeded", "failed") and last.started_at < cutoff):
            due.append(image)
    return due
