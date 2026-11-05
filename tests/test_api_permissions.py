"""RBAC, CSRF and tenant-boundary checks."""

from __future__ import annotations

from fastapi.testclient import TestClient


def _add_member(client: TestClient, csrf: str, email: str, role: str) -> dict:
    response = client.post(
        "/api/users",
        headers={"X-CSRF-Token": csrf},
        json={
            "email": email,
            "display_name": role,
            "password": "MemberPass123",
            "role": role,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["data"]


def _token_for(client: TestClient, email: str) -> str:
    response = client.post(
        "/api/auth/login", json={"email": email, "password": "MemberPass123"}
    )
    assert response.status_code == 200, response.text
    return response.json()["data"]["token"]


def test_viewer_is_read_only(client: TestClient, bootstrap_admin: dict) -> None:
    _add_member(client, bootstrap_admin["csrf_token"], "viewer@aegis.test", "viewer")
    token = _token_for(client, "viewer@aegis.test")
    headers = {"Authorization": f"Bearer {token}"}

    assert client.get("/api/dashboard/summary", headers=headers).status_code == 200
    write = client.post("/api/clients", headers=headers, json={"name": "不应创建"})
    assert write.status_code == 403
    assert write.json()["error"]["code"] == "AEG-3002"
    assert client.get("/api/users", headers=headers).status_code == 403


def test_consultant_cannot_manage_users(client: TestClient, bootstrap_admin: dict) -> None:
    _add_member(client, bootstrap_admin["csrf_token"], "consultant@aegis.test", "consultant")
    token = _token_for(client, "consultant@aegis.test")
    headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/users", headers=headers).status_code == 403
    assert client.post(
        "/api/clients", headers=headers, json={"name": "咨询顾问创建的客户"}
    ).status_code == 201


def test_cookie_write_requires_csrf(client: TestClient, bootstrap_admin: dict) -> None:
    response = client.post("/api/clients", json={"name": "缺少 CSRF"})
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "AEG-3003"


def test_bearer_write_skips_csrf(client: TestClient, bootstrap_admin: dict) -> None:
    response = client.post(
        "/api/clients",
        headers={"Authorization": f"Bearer {bootstrap_admin['token']}"},
        json={"name": "Bearer 请求"},
    )
    assert response.status_code == 201


def test_last_admin_cannot_be_demoted(client: TestClient, bootstrap_admin: dict) -> None:
    response = client.patch(
        f"/api/users/{bootstrap_admin['user']['id']}",
        headers={"X-CSRF-Token": bootstrap_admin["csrf_token"]},
        json={"role": "consultant"},
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "AEG-2002"


def test_last_admin_cannot_be_deactivated(client: TestClient, bootstrap_admin: dict) -> None:
    response = client.patch(
        f"/api/users/{bootstrap_admin['user']['id']}",
        headers={"X-CSRF-Token": bootstrap_admin["csrf_token"]},
        json={"is_active": False},
    )
    assert response.status_code == 409


def test_second_admin_allows_demotion(client: TestClient, bootstrap_admin: dict) -> None:
    _add_member(client, bootstrap_admin["csrf_token"], "admin2@aegis.test", "admin")
    response = client.patch(
        f"/api/users/{bootstrap_admin['user']['id']}",
        headers={"X-CSRF-Token": bootstrap_admin["csrf_token"]},
        json={"role": "consultant"},
    )
    assert response.status_code == 200
    assert response.json()["data"]["role"] == "consultant"
