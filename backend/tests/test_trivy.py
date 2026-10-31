import json
from pathlib import Path

import pytest

from kubeshield.scanners import trivy

REPORT = json.loads((Path(__file__).parent / "fixtures" / "trivy_report.json").read_text())


def test_parse_report():
    parsed = trivy.parse_report(REPORT)
    vulns = parsed["vulnerabilities"]
    assert len(vulns) == 3  # duplicate CVE/package collapsed
    musl = vulns[0]
    assert musl["vuln_id"] == "CVE-2019-14697" and musl["cvss_score"] == 9.8
    assert musl["fixed_version"] == "1.1.22-r3" and musl["severity"] == "critical"
    apk = vulns[1]
    assert apk["fixed_version"] is None and apk["cvss_score"] == 7.5
    assert vulns[2]["severity"] == "info"
    assert parsed["counts"] == {"critical": 1, "high": 1, "medium": 0, "low": 0, "info": 1}
    assert parsed["os_family"] == "alpine 3.10.0" and parsed["digest"].startswith("sha256:")
    kinds = [(f["kind"], f["rule_id"]) for f in parsed["findings"]]
    assert kinds == [("secret", "aws-access-key-id"), ("misconfig", "AVD-DS-0002")]


def test_secret_values_are_never_stored():
    parsed = trivy.parse_report(REPORT)
    assert "****" not in json.dumps(parsed) and "AWS_KEY" not in json.dumps(parsed)


@pytest.mark.parametrize("image", ["nginx:1.27", "docker.io/library/alpine:3.10.0",
                                   "ghcr.io/org/app@sha256:" + "a" * 64, "localhost:5000/x/y:z"])
def test_valid_images(image):
    assert trivy.validate_image(image) == image


@pytest.mark.parametrize("image", ["--help", "nginx; rm -rf /", "nginx latest", "../etc/passwd", "a" * 300,
                                   "NGINX", "$(id)"])
def test_invalid_images(image):
    with pytest.raises(ValueError):
        trivy.validate_image(image)


def test_sbom_summary():
    sbom = {"specVersion": "1.6", "components": [{"name": "musl", "version": "1.1.22-r2", "type": "library",
                                                  "purl": "pkg:apk/alpine/musl@1.1.22-r2"}] * 3}
    s = trivy.summarize_sbom(sbom, limit=2)
    assert s["component_count"] == 3 and len(s["components"]) == 2 and s["truncated"]
