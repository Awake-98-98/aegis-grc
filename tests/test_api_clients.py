"""Client API behaviour."""

from __future__ import annotations

from fastapi.testclient import TestClient


def _create(client: TestClient, csrf: str, **overrides):
    payload = {"name": "示例客户", "industry": "制造", "contact_name": "张三"}
    payload.update(overrides)
    return client.post("/api/clients", headers={"X-CSRF-Token": csrf}, json=payload)


def test_create_and_read_client(client: TestClient, bootstrap_admin: dict) -> None:
    created = _create(client, bootstrap_admin["csrf_token"], contact_email="a@b.test")
    assert created.status_code == 201
    data = created.json()["data"]
    assert data["code"] == "CL-0001"
    assert data["status"] == "prospect"
    assert data["engagement_count"] == 0

    fetched = client.get(f"/api/clients/{data['id']}")
    assert fetched.status_code == 200
    assert fetched.json()["data"]["name"] == "示例客户"


def test_auto_codes_increment(client: TestClient, bootstrap_admin: dict) -> None:
    first = _create(client, bootstrap_admin["csrf_token"], name="客户一").json()["data"]
    second = _create(client, bootstrap_admin["csrf_token"], name="客户二").json()["data"]
    assert first["code"] == "CL-0001"
    assert second["code"] == "CL-0002"


def test_explicit_code_conflict(client: TestClient, bootstrap_admin: dict) -> None:
    _create(client, bootstrap_admin["csrf_token"], name="客户一", code="CL-9000")
    conflict = _create(client, bootstrap_admin["csrf_token"], name="客户二", code="CL-9000")
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "AEG-2002"


def test_invalid_email_is_rejected(client: TestClient, bootstrap_admin: dict) -> None:
    response = _create(client, bootstrap_admin["csrf_token"], contact_email="not-an-email")
    assert response.status_code == 422
    assert response.json()["error"]["details"]["field"] == "contact_email"


def test_unknown_status_is_rejected(client: TestClient, bootstrap_admin: dict) -> None:
    response = _create(client, bootstrap_admin["csrf_token"], status="unknown")
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "AEG-2003"


def test_update_client_and_audit(client: TestClient, bootstrap_admin: dict) -> None:
    created = _create(client, bootstrap_admin["csrf_token"]).json()["data"]
    updated = client.patch(
        f"/api/clients/{created['id']}",
        headers={"X-CSRF-Token": bootstrap_admin["csrf_token"]},
        json={"name": "改名后的客户", "status": "active"},
    )
    assert updated.status_code == 200
    assert updated.json()["data"]["status"] == "active"

    audit = client.get("/api/audit", params={"entity_type": "client"}).json()
    actions = [item["action"] for item in audit["data"]]
    assert "client.create" in actions
    assert "client.update" in actions


def test_list_filters_and_pagination(client: TestClient, bootstrap_admin: dict) -> None:
    for index in range(3):
        _create(client, bootstrap_admin["csrf_token"], name=f"批量客户 {index}")
    _create(client, bootstrap_admin["csrf_token"], name="特殊行业", industry="金融")

    response = client.get("/api/clients", params={"q": "金融"})
    assert response.status_code == 200
    assert len(response.json()["data"]) == 1

    paged = client.get("/api/clients", params={"page": 1, "page_size": 2}).json()
    assert len(paged["data"]) == 2
    assert paged["meta"]["total"] == 4
    assert paged["meta"]["pages"] == 2


def test_missing_client_returns_404(client: TestClient, bootstrap_admin: dict) -> None:
    response = client.get("/api/clients/does-not-exist")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "AEG-2001"
