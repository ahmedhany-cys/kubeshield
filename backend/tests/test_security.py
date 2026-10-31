import jwt
from conftest import HEADERS, login

from kubeshield.config import get_settings
from kubeshield.security import LoginRateLimiter


def test_requires_authentication(client):
    for path in ("/api/v1/events", "/api/v1/overview", "/api/v1/incidents", "/api/v1/settings"):
        assert client.get(path).status_code == 401


def test_login_sets_httponly_strict_cookie(client):
    r = login(client)
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    assert client.get("/api/v1/auth/me").json() == {"username": "admin", "role": "admin"}


def test_wrong_password_and_rate_limit(client):
    for _ in range(5):
        assert client.post("/api/v1/auth/login", json={"username": "admin", "password": "nope"}).status_code == 401
    r = client.post("/api/v1/auth/login", json={"username": "admin", "password": "test-admin-password-1"})
    assert r.status_code == 429


def test_tampered_and_expired_tokens_rejected(client):
    forged = jwt.encode({"sub": "admin", "role": "admin", "iss": "kubeshield", "exp": 9999999999}, "x" * 32,
                        algorithm="HS256")
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {forged}"}).status_code == 401
    expired = jwt.encode({"sub": "admin", "role": "admin", "iss": "kubeshield", "exp": 1},
                         get_settings().jwt_secret.get_secret_value(), algorithm="HS256")
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {expired}"}).status_code == 401
    none_alg = jwt.encode({"sub": "admin", "iss": "kubeshield", "exp": 9999999999}, None, algorithm="none")
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {none_alg}"}).status_code == 401


def test_security_headers(client):
    r = client.get("/healthz")
    assert r.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"


def test_csrf_header_required_for_mutations(admin):
    body = {"key": "simulation.enabled", "value": False}
    assert admin.put("/api/v1/settings", json=body).status_code == 403
    assert admin.put("/api/v1/settings", json=body, headers=HEADERS).status_code == 200


def test_settings_validation_and_audit(admin):
    assert admin.put("/api/v1/settings", json={"key": "nope", "value": True}, headers=HEADERS).status_code == 404
    assert admin.put("/api/v1/settings", json={"key": "response.auto_enabled", "value": "yes"},
                     headers=HEADERS).status_code == 422
    r = admin.put("/api/v1/settings", json={"key": "response.auto_enabled", "value": True}, headers=HEADERS)
    assert r.json()["response.auto_enabled"] is True
    audit = admin.get("/api/v1/audit", params={"action": "settings."}).json()
    assert audit[0]["details"] == {"from": False, "to": True}


def test_manual_response_input_validation(admin):
    bad = {"action_type": "isolate_pod", "namespace": "Lab_Apps", "name": "x"}
    assert admin.post("/api/v1/responses", json=bad, headers=HEADERS).status_code == 422
    unknown = {"action_type": "rm_rf", "namespace": "lab-apps", "name": "x"}
    assert admin.post("/api/v1/responses", json=unknown, headers=HEADERS).status_code == 422


def test_rate_limiter_window():
    rl = LoginRateLimiter(max_attempts=2, window_seconds=60)
    rl.fail("k")
    assert not rl.blocked("k")
    rl.fail("k")
    assert rl.blocked("k")
    rl.reset("k")
    assert not rl.blocked("k")
