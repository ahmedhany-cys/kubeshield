import pytest
from conftest import HEADERS, falco_alert, login
from fakes import FakeKube

from kubeshield import ingest, settings_store
from kubeshield.models import Playbook, ResponseAction
from kubeshield.response import actions, engine


@pytest.fixture()
def fake(monkeypatch):
    fk = FakeKube()
    fk.add_pod("lab-apps", "storefront-abc")
    monkeypatch.setattr(engine, "kube", fk)
    monkeypatch.setattr(actions, "kube", fk)
    monkeypatch.setattr(actions, "sanitize", lambda o: {"stub": True})
    return fk


def _ingest(db, **kw):
    ev, _ = ingest.store_event(db, ingest.normalize_falco(falco_alert(**kw)))
    return ev


def test_credential_access_requests_approval_not_execution(db, fake):
    ev = _ingest(db)
    acts = db.query(ResponseAction).filter_by(incident_id=ev.incident_id).all()
    types = {a.action_type: a.status for a in acts}
    assert types == {"isolate_pod": "pending_approval", "delete_pod": "pending_approval"}
    assert not fake.cnps and fake.pods  # nothing changed in the cluster


def test_alert_only_playbook_records_without_change(db, fake):
    ev = _ingest(db, rule="KubeShield Shell Spawned in Container", priority="Warning",
                 tags=["kubeshield", "ks.001", "T1059.004"])
    (a,) = db.query(ResponseAction).filter_by(incident_id=ev.incident_id).all()
    assert a.action_type == "alert_only" and a.status == "alerted" and a.mode == "alert_only"


def test_auto_mode_falls_back_to_approval_when_globally_disabled(db, fake):
    db.query(Playbook).delete()
    db.add(Playbook(name="auto isolate", match_rule_ids=["ks.004"], min_severity="high",
                    action_type="isolate_pod", mode="auto"))
    db.flush()
    ev = _ingest(db)
    (a,) = db.query(ResponseAction).filter_by(incident_id=ev.incident_id).all()
    assert a.status == "pending_approval" and "disabled globally" in a.reason


def test_destructive_auto_never_runs_by_default(db, fake):
    settings_store.set_value(db, "response.auto_enabled", True, "test")
    db.query(Playbook).delete()
    db.add(Playbook(name="auto delete", match_rule_ids=["ks.004"], min_severity="high",
                    action_type="delete_pod", mode="auto"))
    db.flush()
    ev = _ingest(db)
    (a,) = db.query(ResponseAction).filter_by(incident_id=ev.incident_id).all()
    assert a.status == "pending_approval" and "never automatic" in a.reason
    assert ("lab-apps", "storefront-abc") in fake.pods


def test_auto_isolation_executes_and_verifies(app, fake):
    from kubeshield.db import session_scope

    with session_scope() as db:
        settings_store.set_value(db, "response.auto_enabled", True, "test")
        db.query(Playbook).delete()
        db.add(Playbook(name="auto isolate", match_rule_ids=["ks.004"], min_severity="high",
                        action_type="isolate_pod", mode="auto"))
    with session_scope() as db:
        ev = _ingest(db)
        incident_id = ev.incident_id
    with session_scope() as db:
        (a,) = db.query(ResponseAction).filter_by(incident_id=incident_id).all()
        assert a.status == "succeeded", a.error
        assert a.verification["verified"] is True
        assert a.result["engine"] == "cilium-deny-policy"
        from kubeshield.models import Incident

        assert db.get(Incident, incident_id).status == "contained"
    pod = fake.pods[("lab-apps", "storefront-abc")]
    assert pod.metadata.labels[actions.QUARANTINE_LABEL] == f"inc-{incident_id}"
    (cnp,) = fake.cnps.values()
    assert cnp["spec"]["egressDeny"] and cnp["spec"]["ingressDeny"]


def test_isolation_without_cilium_uses_networkpolicy_with_caveat(app, fake):
    from kubeshield.db import session_scope

    fake.cilium = False
    with session_scope() as db:
        a = engine.request_manual(db, None, "isolate_pod", "lab-apps", "storefront-abc", "analyst", "test")
        engine.schedule(db, a.id)
        aid = a.id
    with session_scope() as db:
        a = db.get(ResponseAction, aid)
        assert a.status == "succeeded"
        assert a.result["engine"] == "kubernetes-networkpolicy" and "additive" in a.result["caveat"]
    assert fake.netpols


def test_lab_guard_refuses_non_lab_namespace(app, fake):
    from kubeshield.db import session_scope

    fake.add_pod("production", "api-1")
    with session_scope() as db:
        a = engine.request_manual(db, None, "delete_pod", "production", "api-1", "analyst", "")
        engine.schedule(db, a.id)
        aid = a.id
    with session_scope() as db:
        a = db.get(ResponseAction, aid)
        assert a.status == "refused" and "not part of the lab" in a.error
    assert ("production", "api-1") in fake.pods


def test_delete_pod_captures_forensics(app, fake):
    from kubeshield.db import session_scope

    with session_scope() as db:
        a = engine.request_manual(db, None, "delete_pod", "lab-apps", "storefront-abc", "analyst", "")
        engine.schedule(db, a.id)
        aid = a.id
    with session_scope() as db:
        a = db.get(ResponseAction, aid)
        assert a.status == "succeeded"
        assert a.result["forensics"]["log_tail"] == "log line\n"
        assert a.result["forensics"]["images"] == ["busybox:1.37"]
    assert ("lab-apps", "storefront-abc") not in fake.pods


def test_failed_action_is_recorded(app, fake):
    from kubeshield.db import session_scope

    with session_scope() as db:
        a = engine.request_manual(db, None, "isolate_pod", "lab-apps", "missing-pod", "analyst", "")
        engine.schedule(db, a.id)
        aid = a.id
    with session_scope() as db:
        a = db.get(ResponseAction, aid)
        assert a.status == "failed" and "404" in a.error and a.completed_at is not None


def test_api_approval_workflow_and_roles(client, ingest_headers, fake, db):
    from kubeshield.models import User
    from kubeshield.security import hash_password

    db.add(User(username="viewer", password_hash=hash_password("viewer-password-1"), role="viewer"))
    db.add(User(username="responder", password_hash=hash_password("responder-password-1"), role="responder"))
    db.commit()
    inc_id = client.post("/api/v1/ingest/falco", json=falco_alert(), headers=ingest_headers).json()["incident_id"]

    login(client, "viewer", "viewer-password-1")
    actions_ = client.get(f"/api/v1/incidents/{inc_id}").json()["actions"]
    isolate = next(a for a in actions_ if a["action_type"] == "isolate_pod")
    delete = next(a for a in actions_ if a["action_type"] == "delete_pod")
    r = client.post(f"/api/v1/responses/{isolate['id']}/decision", json={"approve": True}, headers=HEADERS)
    assert r.status_code == 403

    login(client, "responder", "responder-password-1")
    r = client.post(f"/api/v1/responses/{delete['id']}/decision", json={"approve": True}, headers=HEADERS)
    assert r.status_code == 403  # destructive needs admin
    r = client.post(f"/api/v1/responses/{isolate['id']}/decision", json={"approve": True})
    assert r.status_code == 403 and "X-Requested-With" in r.text  # CSRF header enforced
    r = client.post(f"/api/v1/responses/{isolate['id']}/decision", json={"approve": True, "note": "ok"},
                    headers=HEADERS)
    assert r.status_code == 200
    final = client.get(f"/api/v1/responses/{isolate['id']}").json()
    assert final["status"] == "succeeded" and final["decided_by"] == "responder"
    trail = [e["action"] for e in client.get(f"/api/v1/incidents/{inc_id}").json()["audit_trail"]]
    assert "response.approved" in trail and "response.succeeded" in trail
    r = client.post(f"/api/v1/responses/{isolate['id']}/decision", json={"approve": True}, headers=HEADERS)
    assert r.status_code == 409


def test_isolation_fails_verification_when_cilium_never_enforces(app, fake, monkeypatch):
    from kubeshield.db import session_scope

    fake.stale_identity = True
    monkeypatch.setattr(actions, "ENFORCEMENT_TIMEOUT_SECONDS", 0)
    with session_scope() as db:
        a = engine.request_manual(db, None, "isolate_pod", "lab-apps", "storefront-abc", "analyst", "")
        engine.schedule(db, a.id)
        aid = a.id
    with session_scope() as db:
        a = db.get(ResponseAction, aid)
        assert a.status == "failed" and a.error == "post-action verification failed"
        enforced = a.verification["checks"][-1]
        assert enforced["passed"] is False and enforced["observed"]["identity_has_quarantine_label"] is False


def test_namespace_containment_denies_api_server_and_keeps_dns(app, fake):
    from kubeshield.db import session_scope

    with session_scope() as db:
        a = engine.request_manual(db, None, "contain_namespace", "lab-apps", "lab-apps", "analyst", "")
        engine.schedule(db, a.id)
        aid = a.id
    with session_scope() as db:
        assert db.get(ResponseAction, aid).status == "succeeded"
    (cnp,) = fake.cnps.values()
    spec = cnp["spec"]
    assert spec["enableDefaultDeny"] == {"egress": False, "ingress": False}
    assert {"kube-apiserver", "world"} <= set(spec["egressDeny"][0]["toEntities"])
    with session_scope() as db:
        r = engine.request_manual(db, None, "release_containment", "lab-apps", "lab-apps", "analyst", "")
        engine.schedule(db, r.id)
        rid = r.id
    with session_scope() as db:
        assert db.get(ResponseAction, rid).status == "succeeded"
    assert not fake.cnps
