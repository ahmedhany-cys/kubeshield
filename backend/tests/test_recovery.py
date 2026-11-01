from kubeshield.main import fail_interrupted_work
from kubeshield.models import AuditLog, ImageScan, ResponseAction, SimulationRun


def _action(status: str) -> ResponseAction:
    return ResponseAction(action_type="isolate_pod", mode="approval", status=status, target_namespace="lab-apps",
                          target_kind="Pod", target_name="storefront-abc", requested_by="playbook")


def test_interrupted_work_is_failed_not_replayed(db):
    run = SimulationRun(scenario_id="shell-in-container", status="running", requested_by="admin")
    scan = ImageScan(image="docker.io/library/alpine:3.10.0", status="running", trigger="manual",
                     requested_by="admin")
    executing, approved, pending, done = (_action(s) for s in ("executing", "approved", "pending_approval",
                                                               "succeeded"))
    db.add_all([run, scan, executing, approved, pending, done])
    db.flush()

    counts = fail_interrupted_work(db)

    assert counts == {"simulations": 1, "scans": 1, "responses": 2}
    assert run.status == "error" and run.finished_at is not None
    # simulation.start() refuses while any run is "running"; none is left to block it.
    assert db.query(SimulationRun).filter_by(status="running").count() == 0
    assert scan.status == "failed"
    assert executing.status == approved.status == "failed"
    assert "may have partly applied" in executing.error
    # Work that was not in flight is left alone: nothing pending is approved or executed on restart.
    assert pending.status == "pending_approval" and done.status == "succeeded"
    assert db.query(AuditLog).filter_by(action="response.failed").count() == 2

