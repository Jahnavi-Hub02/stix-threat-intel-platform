"""
tests/test_auth.py
==================
Full test suite for JWT authentication.
"""

import pytest
import time


# ══════════════════════════════════════════════════════════════════
# Fixtures
# ══════════════════════════════════════════════════════════════════

@pytest.fixture
def client(temp_db):
    """
    Uses 'with' so lifespan startup/shutdown brackets each test.
    Ensures all SQLite connections are flushed before the next test.
    """
    from fastapi.testclient import TestClient
    from app.api.main import app
    with TestClient(app) as c:
        yield c


def _register(client, username, password="Password123!", role="viewer"):
    return client.post("/auth/register", json={
        "username": username,
        "password": password,
        "role": role,
    })


def _login(client, username, password="Password123!"):
    return client.post("/auth/login", json={
        "username": username,
        "password": password,
    })


def _get_token(client, username="testviewer", role="viewer"):
    """Register + login, return access_token string."""
    _register(client, username, role=role)
    r = _login(client, username)
    return r.json()["access_token"]


def _auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ══════════════════════════════════════════════════════════════════
# Password Hashing
# ══════════════════════════════════════════════════════════════════

class TestPasswordHashing:

    def test_hash_is_not_plaintext(self):
        from app.auth.security import hash_password
        h = hash_password("mysecret")
        assert "mysecret" not in h

    def test_hash_format(self):
        from app.auth.security import hash_password
        h = hash_password("mysecret")
        parts = h.split("$")
        assert parts[0] == "pbkdf2_sha256"
        assert len(parts) == 4

    def test_verify_correct_password(self):
        from app.auth.security import hash_password, verify_password
        h = hash_password("correct-horse-battery")
        assert verify_password("correct-horse-battery", h) is True

    def test_verify_wrong_password(self):
        from app.auth.security import hash_password, verify_password
        h = hash_password("correct")
        assert verify_password("incorrect", h) is False

    def test_two_hashes_of_same_password_differ(self):
        from app.auth.security import hash_password
        h1 = hash_password("same")
        h2 = hash_password("same")
        assert h1 != h2

    def test_verify_malformed_hash(self):
        from app.auth.security import verify_password
        assert verify_password("password", "not-a-valid-hash") is False

    def test_verify_empty_password_fails(self):
        from app.auth.security import hash_password, verify_password
        h = hash_password("correct")
        assert verify_password("", h) is False


# ══════════════════════════════════════════════════════════════════
# JWT Token Logic
# ══════════════════════════════════════════════════════════════════

class TestJWTTokens:

    def test_access_token_decodes(self):
        from app.auth.security import create_access_token, decode_token
        token, _ = create_access_token(1, "alice", "analyst")
        payload  = decode_token(token)
        assert payload["sub"]     == "alice"
        assert payload["user_id"] == 1
        assert payload["role"]    == "analyst"
        assert payload["type"]    == "access"

    def test_refresh_token_decodes(self):
        from app.auth.security import create_refresh_token, decode_token
        token, jti = create_refresh_token(1, "alice")
        payload    = decode_token(token)
        assert payload["type"]    == "refresh"
        assert payload["user_id"] == 1
        assert payload["jti"]     == jti

    def test_expired_token_raises_401(self):
        import jwt as pyjwt
        from app.auth.security import SECRET_KEY, ALGORITHM, decode_token
        from fastapi import HTTPException
        payload = {"sub": "alice", "user_id": 1, "role": "viewer",
                   "type": "access", "exp": 1, "iat": 1}
        token = pyjwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
        with pytest.raises(HTTPException) as exc_info:
            decode_token(token)
        assert exc_info.value.status_code == 401
        assert "expired" in exc_info.value.detail.lower()

    def test_tampered_token_raises_401(self):
        from app.auth.security import create_access_token, decode_token
        from fastapi import HTTPException
        token, _ = create_access_token(1, "alice", "viewer")
        tampered = token[:-5] + "XXXXX"
        with pytest.raises(HTTPException) as exc_info:
            decode_token(tampered)
        assert exc_info.value.status_code == 401

    def test_access_token_expires_in_seconds(self):
        from app.auth.security import create_access_token, ACCESS_TOKEN_MINS
        _, expires_in = create_access_token(1, "alice", "viewer")
        assert expires_in == ACCESS_TOKEN_MINS * 60

    def test_refresh_token_has_jti(self):
        from app.auth.security import create_refresh_token
        _, jti = create_refresh_token(1, "alice")
        assert len(jti) == 32

    def test_verify_token_dep_requires_access_type(self, client):
        from app.auth.security import create_refresh_token
        refresh_token, _ = create_refresh_token(1, "alice")
        r = client.get("/metrics", headers=_auth_header(refresh_token))
        assert r.status_code == 401

    def test_require_role_hierarchy(self):
        from app.auth.security import ROLE_HIERARCHY
        assert ROLE_HIERARCHY.index("viewer")  < ROLE_HIERARCHY.index("analyst")
        assert ROLE_HIERARCHY.index("analyst") < ROLE_HIERARCHY.index("admin")


# ══════════════════════════════════════════════════════════════════
# Register Endpoint
# ══════════════════════════════════════════════════════════════════

class TestRegister:

    def test_register_success(self, client):
        r = _register(client, "newuser")
        assert r.status_code == 201
        data = r.json()
        assert data["username"] == "newuser"
        assert data["role"]     == "viewer"
        assert "user_id"        in data
        assert "password"       not in data
        assert "password_hash"  not in data

    def test_register_returns_role(self, client):
        r = _register(client, "analystuser", role="analyst")
        assert r.status_code == 201
        assert r.json()["role"] == "analyst"

    def test_register_duplicate_username(self, client):
        _register(client, "dupuser")
        r = _register(client, "dupuser")
        assert r.status_code == 409
        assert "taken" in r.json()["detail"].lower()

    def test_register_invalid_username_chars(self, client):
        r = _register(client, "bad user!")
        assert r.status_code == 422

    def test_register_too_short_username(self, client):
        r = _register(client, "ab")
        assert r.status_code == 422

    def test_register_short_password(self, client):
        r = client.post("/auth/register", json={
            "username": "shortpw", "password": "1234567", "role": "viewer"
        })
        assert r.status_code == 422

    def test_register_invalid_role(self, client):
        r = client.post("/auth/register", json={
            "username": "badrole", "password": "Password123!", "role": "superuser"
        })
        assert r.status_code == 422

    def test_register_username_case_insensitive(self, client):
        _register(client, "CaseUser")
        r = _register(client, "caseuser")
        assert r.status_code == 409


# ══════════════════════════════════════════════════════════════════
# Login Endpoint
# ══════════════════════════════════════════════════════════════════

class TestLogin:

    def test_login_success(self, client):
        _register(client, "loginuser")
        r = _login(client, "loginuser")
        assert r.status_code == 200
        data = r.json()
        assert "access_token"  in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert data["username"]   == "loginuser"
        assert data["role"]       == "viewer"
        assert data["expires_in"] > 0

    def test_login_wrong_password(self, client):
        _register(client, "wrongpw")
        r = client.post("/auth/login", json={"username": "wrongpw", "password": "WrongPass!"})
        assert r.status_code == 401

    def test_login_nonexistent_user(self, client):
        r = _login(client, "nobody")
        assert r.status_code == 401

    def test_login_case_insensitive_username(self, client):
        _register(client, "CaseSensitive")
        r = _login(client, "casesensitive")
        assert r.status_code == 200

    def test_login_returns_valid_jwt(self, client):
        _register(client, "jwtuser")
        r       = _login(client, "jwtuser")
        token   = r.json()["access_token"]
        from app.auth.security import decode_token
        payload = decode_token(token)
        assert payload["sub"] == "jwtuser"


# ══════════════════════════════════════════════════════════════════
# Refresh & Logout Endpoints
# ══════════════════════════════════════════════════════════════════

class TestRefreshLogout:

    def test_refresh_returns_new_access_token(self, client):
        _register(client, "refreshuser")
        login_data    = _login(client, "refreshuser").json()
        refresh_token = login_data["refresh_token"]
        r = client.post("/auth/refresh", json={"refresh_token": refresh_token})
        assert r.status_code == 200
        data = r.json()
        assert "access_token"    in data
        assert data["token_type"] == "bearer"

    def test_refresh_with_access_token_fails(self, client):
        token = _get_token(client, "wrongrefresh")
        r = client.post("/auth/refresh", json={"refresh_token": token})
        assert r.status_code == 401

    def test_logout_revokes_refresh_token(self, client):
        _register(client, "logoutuser")
        login_data    = _login(client, "logoutuser").json()
        refresh_token = login_data["refresh_token"]
        client.post("/auth/logout", json={"refresh_token": refresh_token})
        r = client.post("/auth/refresh", json={"refresh_token": refresh_token})
        assert r.status_code == 401

    def test_logout_returns_200_even_for_expired_token(self, client):
        r = client.post("/auth/logout", json={"refresh_token": "garbage.token.here"})
        assert r.status_code == 200


# ══════════════════════════════════════════════════════════════════
# /auth/me
# ══════════════════════════════════════════════════════════════════

class TestMe:

    def test_me_returns_user_info(self, client):
        token = _get_token(client, "meuser", role="analyst")
        r     = client.get("/auth/me", headers=_auth_header(token))
        assert r.status_code == 200
        data = r.json()
        assert data["username"] == "meuser"
        assert data["role"]     == "analyst"
        assert "user_id"    in data
        assert "expires_at" in data

    def test_me_without_token_returns_401(self, client):
        r = client.get("/auth/me")
        assert r.status_code == 401


# ══════════════════════════════════════════════════════════════════
# Protected Endpoint Access Control
# ══════════════════════════════════════════════════════════════════

class TestAccessControl:

    def test_metrics_requires_token(self, client):
        assert client.get("/metrics").status_code == 401

    def test_iocs_requires_token(self, client):
        assert client.get("/iocs").status_code == 401

    def test_correlations_requires_token(self, client):
        assert client.get("/correlations").status_code == 401

    def test_event_requires_token(self, client):
        r = client.post("/event", json={
            "event_id": "x", "source_ip": "1.2.3.4", "destination_ip": "5.6.7.8"
        })
        assert r.status_code == 401

    def test_ml_status_requires_token(self, client):
        assert client.get("/ml/status").status_code == 401

    def test_viewer_can_read_iocs(self, client):
        token = _get_token(client, "viewer1", role="viewer")
        assert client.get("/iocs", headers=_auth_header(token)).status_code == 200

    def test_viewer_can_read_metrics(self, client):
        token = _get_token(client, "viewer2", role="viewer")
        assert client.get("/metrics", headers=_auth_header(token)).status_code == 200

    def test_viewer_blocked_from_submit_event(self, client):
        token = _get_token(client, "viewer3", role="viewer")
        r     = client.post("/event", headers=_auth_header(token), json={
            "event_id": "evt-block", "source_ip": "1.2.3.4", "destination_ip": "5.6.7.8"
        })
        assert r.status_code == 403
        assert "analyst" in r.json()["detail"].lower()

    def test_viewer_blocked_from_ml_train(self, client):
        token = _get_token(client, "viewer4", role="viewer")
        assert client.post("/ml/train", headers=_auth_header(token)).status_code == 403

    def test_analyst_can_submit_event(self, client):
        token = _get_token(client, "analyst1", role="analyst")
        r     = client.post("/event", headers=_auth_header(token), json={
            "event_id": "analyst-evt-01",
            "source_ip": "1.2.3.4",
            "destination_ip": "5.6.7.8",
            "destination_port": 443,
        })
        assert r.status_code == 200
        assert r.json()["status"] in ("benign", "threat_detected", "anomaly_detected", "confirmed_threat")

    def test_analyst_can_train_ml(self, client):
        token = _get_token(client, "analyst2", role="analyst")
        assert client.post("/ml/train", headers=_auth_header(token)).status_code == 200

    def test_admin_can_do_everything_analyst_can(self, client):
        # Bootstrap admin via DB — correct signature: create_user(username, password_hash, role)
        from app.database.db_manager import create_user
        from app.auth.security import hash_password
        create_user("admin1", hash_password("Password123!"), "admin")
        r     = _login(client, "admin1")
        token = r.json()["access_token"]
        r = client.post("/event", headers=_auth_header(token), json={
            "event_id": "admin-evt-01",
            "source_ip": "1.2.3.4",
            "destination_ip": "5.6.7.8",
        })
        assert r.status_code == 200

    def test_health_is_public(self, client):
        assert client.get("/").status_code       == 200
        assert client.get("/health").status_code == 200

    def test_docs_is_public(self, client):
        assert client.get("/docs").status_code == 200


# ══════════════════════════════════════════════════════════════════
# Admin: User Management
# ══════════════════════════════════════════════════════════════════

@pytest.fixture
def admin_client_and_token(temp_db):
    """
    Isolated admin fixture — each test gets its own fresh DB via temp_db.

    WHY THIS WORKS:
    - temp_db patches DB_PATH to a unique tmp file per test (fully isolated)
    - We insert the admin directly via create_user(username, password_hash, role)
      so there is no dependency on any existing admin token
    - The TestClient 'with' block ensures the lifespan (create_tables, scheduler)
      runs against the patched temp DB — same file the insert uses
    - After yield, we force-stop the APScheduler background thread so it
      releases its SQLite connection before the next test's temp_db is set up.
      Without this teardown the background thread keeps the previous DB file
      open and subsequent create_user() calls hit 'database is locked'.
    """
    from fastapi.testclient import TestClient
    from app.api.main import app
    from app.database.db_manager import create_user
    from app.auth.security import hash_password

    with TestClient(app) as c:
        # Correct call: create_user(username, password_hash, role)
        create_user("adminuser", hash_password("Password123!"), "admin")
        r     = _login(c, "adminuser")
        token = r.json()["access_token"]
        yield c, token

    # ── Teardown: stop APScheduler so it releases the DB file lock ──
    try:
        from app.ingestion.scheduler import scheduler as _sched
        if _sched.is_running:
            _sched.scheduler.shutdown(wait=False)
            _sched.is_running = False
    except Exception:
        pass  # Already stopped — fine


class TestAdminUserManagement:

    def test_admin_can_list_users(self, admin_client_and_token):
        client, token = admin_client_and_token
        r = client.get("/auth/users", headers=_auth_header(token))
        assert r.status_code == 200
        assert isinstance(r.json(), list)
        assert any(u["username"] == "adminuser" for u in r.json())

    def test_viewer_cannot_list_users(self, admin_client_and_token):
        client, _ = admin_client_and_token
        token = _get_token(client, "viewer99", role="viewer")
        assert client.get("/auth/users", headers=_auth_header(token)).status_code == 403

    def test_admin_can_deactivate_user(self, admin_client_and_token):
        client, token = admin_client_and_token
        _register(client, "targetuser")
        users  = client.get("/auth/users", headers=_auth_header(token)).json()
        target = next(u for u in users if u["username"] == "targetuser")
        r      = client.delete(f"/auth/users/{target['user_id']}", headers=_auth_header(token))
        assert r.status_code == 200
        assert _login(client, "targetuser").status_code == 401

    def test_admin_cannot_deactivate_self(self, admin_client_and_token):
        client, token = admin_client_and_token
        users = client.get("/auth/users", headers=_auth_header(token)).json()
        admin = next(u for u in users if u["username"] == "adminuser")
        r     = client.delete(f"/auth/users/{admin['user_id']}", headers=_auth_header(token))
        assert r.status_code == 400

    def test_deactivate_nonexistent_user(self, admin_client_and_token):
        client, token = admin_client_and_token
        assert client.delete("/auth/users/99999", headers=_auth_header(token)).status_code == 404
