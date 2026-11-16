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


def test_viewer_can_read_assets_but_not_write_them(
    client: TestClient, bootstrap_admin: dict
) -> None:
    admin = {"X-CSRF-Token": bootstrap_admin["csrf_token"]}
    client.post("/api/clients", json={"name": "权限客户"}, headers=admin)
    client_row = client.get("/api/clients").json()["data"][0]
    engagement = client.post(
        "/api/engagements",
        json={"client_id": client_row["id"], "name": "权限项目"},
        headers=admin,
    ).json()["data"]
    client.post(
        f"/api/engagements/{engagement['id']}/assets",
        json={"name": "权限资产"},
        headers=admin,
    )

    _add_member(client, bootstrap_admin["csrf_token"], "viewer2@aegis.test", "viewer")
    token = _token_for(client, "viewer2@aegis.test")
    headers = {"Authorization": f"Bearer {token}"}

    listing = client.get(f"/api/engagements/{engagement['id']}/assets", headers=headers)
    assert listing.status_code == 200
    assert listing.json()["meta"]["total"] == 1

    denied = client.post(
        f"/api/engagements/{engagement['id']}/assets",
        headers=headers,
        json={"name": "越权资产"},
    )
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "AEG-3002"


def test_viewer_can_read_risks_but_not_write_them(
    client: TestClient, bootstrap_admin: dict
) -> None:
    admin = {"X-CSRF-Token": bootstrap_admin["csrf_token"]}
    client.post("/api/clients", json={"name": "风险权限客户"}, headers=admin)
    client_row = client.get("/api/clients").json()["data"][0]
    engagement = client.post(
        "/api/engagements",
        json={"client_id": client_row["id"], "name": "风险权限项目"},
        headers=admin,
    ).json()["data"]
    assessment = client.post(
        f"/api/engagements/{engagement['id']}/assessments",
        json={"title": "权限评估"},
        headers=admin,
    ).json()["data"]

    _add_member(client, bootstrap_admin["csrf_token"], "viewer3@aegis.test", "viewer")
    token = _token_for(client, "viewer3@aegis.test")
    headers = {"Authorization": f"Bearer {token}"}

    assert client.get(f"/api/assessments/{assessment['id']}", headers=headers).status_code == 200
    denied = client.post(
        f"/api/engagements/{engagement['id']}/assessments",
        headers=headers,
        json={"title": "越权评估"},
    )
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "AEG-3002"


def test_consultant_can_create_assessment(
    client: TestClient, bootstrap_admin: dict
) -> None:
    admin = {"X-CSRF-Token": bootstrap_admin["csrf_token"]}
    client.post("/api/clients", json={"name": "评估权限客户"}, headers=admin)
    client_row = client.get("/api/clients").json()["data"][0]
    engagement = client.post(
        "/api/engagements",
        json={"client_id": client_row["id"], "name": "评估权限项目"},
        headers=admin,
    ).json()["data"]

    _add_member(client, bootstrap_admin["csrf_token"], "consultant3@aegis.test", "consultant")
    token = _token_for(client, "consultant3@aegis.test")
    response = client.post(
        f"/api/engagements/{engagement['id']}/assessments",
        headers={"Authorization": f"Bearer {token}"},
        json={"title": "顾问建立的评估"},
    )
    assert response.status_code == 201, response.text
    assert response.json()["data"]["code"] == "RA-0001"


def test_consultant_can_import_assets(client: TestClient, bootstrap_admin: dict) -> None:
    admin = {"X-CSRF-Token": bootstrap_admin["csrf_token"]}
    client.post("/api/clients", json={"name": "导入权限客户"}, headers=admin)
    client_row = client.get("/api/clients").json()["data"][0]
    engagement = client.post(
        "/api/engagements",
        json={"client_id": client_row["id"], "name": "导入权限项目"},
        headers=admin,
    ).json()["data"]

    _add_member(client, bootstrap_admin["csrf_token"], "consultant2@aegis.test", "consultant")
    token = _token_for(client, "consultant2@aegis.test")
    response = client.post(
        f"/api/engagements/{engagement['id']}/assets/import",
        headers={"Authorization": f"Bearer {token}"},
        files={
            "file": (
                "a.csv",
                b"name,category\nconsultant-imported,server\n",
                "text/csv",
            )
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["data"]["imported"] == 1
