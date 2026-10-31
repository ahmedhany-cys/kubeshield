from conftest import falco_alert

from kubeshield import ingest
from kubeshield.models import Incident


def _store(db, **kw):
    return ingest.store_event(db, ingest.normalize_falco(falco_alert(**kw)))[0]


def test_events_for_same_pod_share_incident(db):
    a = _store(db, rule="KubeShield Shell Spawned in Container", priority="Warning",
               tags=["kubeshield", "ks.001", "T1059.004"])
    b = _store(db)
    assert a.incident_id == b.incident_id
    inc = db.get(Incident, a.incident_id)
    assert inc.event_count == 2 and inc.severity == "critical"
    assert set(inc.rules) == {"ks.001", "ks.004"}
    assert inc.title.startswith("2 correlated detections")


def test_different_pod_gets_new_incident(db):
    a = _store(db, pod="pod-a")
    b = _store(db, pod="pod-b")
    assert a.incident_id != b.incident_id


def test_low_severity_events_do_not_open_incidents(db):
    e = _store(db, rule="Contact K8S API Server From Container", priority="Notice", tags=["T1565"])
    assert e.incident_id is None


def test_attack_chain_escalates_to_high(db):
    for rule, tag in (("KubeShield Shell Spawned in Container", "ks.001"),
                      ("KubeShield Unexpected Outbound Connection", "ks.007"),
                      ("Some upstream rule", "x")):
        e = _store(db, rule=rule, priority="Warning", tags=["kubeshield", tag])
    inc = db.get(Incident, e.incident_id)
    assert len(inc.rules) == 3 and inc.severity == "high"


def test_resolved_incident_is_not_reused(db):
    from kubeshield import incidents

    a = _store(db)
    incidents.set_status(db, db.get(Incident, a.incident_id), "resolved", "analyst")
    b = _store(db)
    assert b.incident_id != a.incident_id
