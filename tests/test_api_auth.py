"""Authentication API behaviour."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_health_is_public(client: TestClient) -> None:
    response = client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["data"]["status"] == "ok"
    assert body["data"]["schema"]["current"] == body["data"]["schema"]["latest"]


def test_setup_status_reflects_bootstrap(client: TestClient, bootstrap_admin: dict) -> None:
    assert client.get("/api/setup/status").json()["data"]["initialized"] is True


def test_bootstrap_only_once(client: TestClient, bootstrap_admin: dict) -> None:
    again = client.post(
        "/api/auth/bootstrap",
        json={"email": "other@aegis.test", "display_name": "X", "password": "AnotherPass123"},
    )
    assert again.status_code == 409
    assert again.json()["error"]["code"] == "AEG-2002"


def test_login_and_me(client: TestClient, bootstrap_admin: dict) -> None:
    me = client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["data"]["user"]["email"] == "admin@aegis.test"
    assert me.json()["data"]["csrf_token"] == bootstrap_admin["csrf_token"]


def test_login_with_wrong_password_is_generic(client: TestClient, bootstrap_admin: dict) -> None:
    client.post("/api/auth/logout", headers={"X-CSRF-Token": bootstrap_admin["csrf_token"]})
    response = client.post(
        "/api/auth/login", json={"email": "admin@aegis.test", "password": "WrongPass123"}
    )
    assert response.status_code == 401
    body = response.json()
    assert body["error"]["message"] == "email or password is incorrect"


def test_login_unknown_email_does_not_leak(client: TestClient) -> None:
    response = client.post(
        "/api/auth/login", json={"email": "ghost@aegis.test", "password": "WrongPass123"}
    )
    assert response.status_code == 401
    assert response.json()["error"]["message"] == "email or password is incorrect"


def test_logout_revokes_session(client: TestClient, bootstrap_admin: dict) -> None:
    response = client.post(
        "/api/auth/logout", headers={"X-CSRF-Token": bootstrap_admin["csrf_token"]}
    )
    assert response.status_code == 200
    assert client.get("/api/auth/me").status_code == 401


def test_logout_requires_csrf(client: TestClient, bootstrap_admin: dict) -> None:
    response = client.post("/api/auth/logout")
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "AEG-3003"


def test_bearer_token_authenticates_without_csrf(client: TestClient, bootstrap_admin: dict) -> None:
    token = bootstrap_admin["token"]
    response = client.post(
        "/api/clients",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": "Bearer 客户"},
    )
    assert response.status_code == 201
    assert client.post(
        "/api/clients",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": "Bearer 客户 2"},
    ).status_code == 201


def test_login_is_rate_limited(client: TestClient, bootstrap_admin: dict) -> None:
    client.post("/api/auth/logout", headers={"X-CSRF-Token": bootstrap_admin["csrf_token"]})
    last = None
    for _ in range(6):
        last = client.post(
            "/api/auth/login",
            json={"email": "admin@aegis.test", "password": "WrongPass123"},
        )
    assert last is not None
    assert last.status_code == 429
    assert last.json()["error"]["code"] == "AEG-3004"


def test_change_password_revokes_old_password(
    client: TestClient, bootstrap_admin: dict
) -> None:
    response = client.post(
        "/api/auth/change-password",
        headers={"X-CSRF-Token": bootstrap_admin["csrf_token"]},
        json={"current_password": "AdminPass123", "new_password": "AdminPass456"},
    )
    assert response.status_code == 200
    client.post("/api/auth/logout", headers={"X-CSRF-Token": bootstrap_admin["csrf_token"]})
    assert client.post(
        "/api/auth/login", json={"email": "admin@aegis.test", "password": "AdminPass123"}
    ).status_code == 401
    assert client.post(
        "/api/auth/login", json={"email": "admin@aegis.test", "password": "AdminPass456"}
    ).status_code == 200


def test_deactivated_user_session_is_invalid(client: TestClient, bootstrap_admin: dict) -> None:
    created = client.post(
        "/api/users",
        headers={"X-CSRF-Token": bootstrap_admin["csrf_token"]},
        json={
            "email": "temp@aegis.test",
            "display_name": "Temp",
            "password": "TempPass1234",
            "role": "consultant",
        },
    )
    assert created.status_code == 201
    user_id = created.json()["data"]["id"]

    login = client.post(
        "/api/auth/login", json={"email": "temp@aegis.test", "password": "TempPass1234"}
    )
    assert login.status_code == 200
    temp_token = login.json()["data"]["token"]
    assert client.get(
        "/api/auth/me", headers={"Authorization": f"Bearer {temp_token}"}
    ).status_code == 200

    # The cookie jar now holds temp's session; administrator actions need a new login.
    admin_login = client.post(
        "/api/auth/login", json={"email": "admin@aegis.test", "password": "AdminPass123"}
    )
    admin_csrf = admin_login.json()["data"]["csrf_token"]
    disabled = client.patch(
        f"/api/users/{user_id}",
        headers={"X-CSRF-Token": admin_csrf},
        json={"is_active": False},
    )
    assert disabled.status_code == 200
    assert client.get(
        "/api/auth/me", headers={"Authorization": f"Bearer {temp_token}"}
    ).status_code == 401
