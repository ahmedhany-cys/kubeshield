from datetime import UTC, datetime

import pytest
from conftest import HEADERS, falco_alert

from kubeshield import ingest


def test_normalize_falco_maps_fields():
    n = ingest.normalize_falco(falco_alert())
    assert n["id"].startswith("falco_")
    assert n["rule_id"] == "ks.004"
    assert n["severity"] == "critical"
    assert n["namespace"] == "lab-apps" and n["pod"] == "storefront-abc"
    assert n["image"] == "docker.io/library/busybox:1.37"
    assert n["process"]["name"] == "cat" and n["process"]["parent"] == "sh"
    assert n["evidence"]["fd.name"].endswith("/token")
    assert n["techniques"] == ["T1528", "T1552.001"]
    assert n["timestamp"] == datetime(2026, 10, 31, 18, 35, 47, 426496, tzinfo=UTC)
    assert "isolate" in n["recommended_response"].lower()


@pytest.mark.parametrize("priority,expected", [("Emergency", "critical"), ("Error", "high"),
                                               ("Warning", "medium"), ("Notice", "low"), ("Debug", "info")])
def test_priority_mapping(priority, expected):
    assert ingest.normalize_falco(falco_alert(priority=priority))["severity"] == expected


def test_upstream_rule_uses_tag_techniques():
    n = ingest.normalize_falco(falco_alert(rule="Read sensitive file untrusted", priority="Warning",
                                           tags=["T1555", "container", "filesystem"]))
    assert n["rule_id"] is None and n["techniques"] == ["T1555"]


def test_rejects_non_falco_payload():
    with pytest.raises(ValueError):
        ingest.normalize_falco({"hello": "world"})


def test_ingest_requires_token(client):
    r = client.post("/api/v1/ingest/falco", json=falco_alert())
    assert r.status_code == 401
    r = client.post("/api/v1/ingest/falco", json=falco_alert(), headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 401


def test_ingest_creates_event_incident_and_is_idempotent(client, ingest_headers, admin):
    alert = falco_alert(uuid="fixed-uuid-1")
    r = client.post("/api/v1/ingest/falco", json=alert, headers=ingest_headers)
    assert r.status_code == 202 and r.json()["created"] is True
    incident_id = r.json()["incident_id"]
    assert incident_id
    r2 = client.post("/api/v1/ingest/falco", json=alert, headers=ingest_headers)
    assert r2.json()["created"] is False
    events = admin.get("/api/v1/events").json()
    assert events["total"] == 1
    inc = admin.get(f"/api/v1/incidents/{incident_id}").json()
    assert inc["event_count"] == 1 and inc["severity"] == "critical"
    assert [a["action"] for a in inc["audit_trail"]][0] == "incident.created"


def test_ingest_rejects_garbage(client, ingest_headers):
    r = client.post("/api/v1/ingest/falco", content=b"not json", headers=ingest_headers)
    assert r.status_code == 422
    big = b"{" + b" " * 1_000_001 + b"}"
    assert client.post("/api/v1/ingest/falco", content=big, headers=ingest_headers).status_code == 413


def test_event_filters_and_search(client, ingest_headers, admin):
    client.post("/api/v1/ingest/falco", json=falco_alert(), headers=ingest_headers)
    client.post("/api/v1/ingest/falco", json=falco_alert(rule="KubeShield Shell Spawned in Container",
                priority="Warning", tags=["kubeshield", "ks.001", "T1059.004"]), headers=ingest_headers)
    assert admin.get("/api/v1/events", params={"severity": "critical"}).json()["total"] == 1
    assert admin.get("/api/v1/events", params={"rule_id": "ks.001"}).json()["total"] == 1
    assert admin.get("/api/v1/events", params={"q": "Shell"}).json()["total"] == 1
    assert admin.get("/api/v1/events", params={"namespace": "other"}).json()["total"] == 0
    assert HEADERS
