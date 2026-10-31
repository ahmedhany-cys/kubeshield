import os
import secrets

os.environ.setdefault("KUBESHIELD_JWT_SECRET", secrets.token_hex(32))
os.environ.setdefault("KUBESHIELD_INGEST_TOKEN", secrets.token_hex(32))
os.environ.setdefault("KUBESHIELD_DATABASE_URL", "sqlite://")
os.environ.setdefault("KUBESHIELD_ADMIN_PASSWORD", "test-admin-password-1")
os.environ.setdefault("KUBESHIELD_COOKIE_SECURE", "false")
os.environ.setdefault("KUBESHIELD_KUBE_MODE", "disabled")
os.environ.setdefault("KUBESHIELD_ENVIRONMENT", "test")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from kubeshield import db as dbmod  # noqa: E402
from kubeshield.config import get_settings  # noqa: E402
from kubeshield.response import engine  # noqa: E402

HEADERS = {"X-Requested-With": "kubeshield"}


@pytest.fixture()
def app():
    from kubeshield.main import bootstrap, create_app
    from kubeshield.security import login_limiter

    login_limiter._failures.clear()
    engine.SYNCHRONOUS = True
    application = create_app(start_workers=False)
    bootstrap()
    yield application
    dbmod.Base.metadata.drop_all(dbmod.get_engine())


@pytest.fixture()
def client(app):
    with TestClient(app) as c:
        yield c


def login(client, username="admin", password="test-admin-password-1"):
    r = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r


@pytest.fixture()
def admin(client):
    login(client)
    return client


@pytest.fixture()
def db(app):
    with dbmod.session_scope() as session:
        yield session


@pytest.fixture()
def ingest_headers():
    return {"Authorization": f"Bearer {get_settings().ingest_token.get_secret_value()}"}


def falco_alert(rule="KubeShield Service Account Token Read", priority="Critical", tags=None, pod="storefront-abc",
                ns="lab-apps", uuid=None, **fields):
    out = {
        "uuid": uuid or secrets.token_hex(8),
        "output": f"{rule} (ks_rule=...)",
        "priority": priority,
        "rule": rule,
        "time": "2026-10-31T18:35:47.426496809Z",
        "source": "syscall",
        "hostname": "kubeshield-lab-control-plane",
        "tags": tags if tags is not None else ["kubeshield", "ks.004", "T1528", "T1552.001"],
        "output_fields": {
            "container.id": "83d23a03eb80", "container.name": "app",
            "container.image.repository": "docker.io/library/busybox", "container.image.tag": "1.37",
            "k8s.ns.name": ns, "k8s.pod.name": pod, "proc.name": "cat",
            "proc.cmdline": "cat /var/run/secrets/kubernetes.io/serviceaccount/token", "proc.pid": 42,
            "proc.pname": "sh", "user.name": "app", "user.uid": 10001,
            "fd.name": "/var/run/secrets/kubernetes.io/serviceaccount/token", **fields,
        },
    }
    return out
