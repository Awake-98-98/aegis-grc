"""Engagement lifecycle and stakeholder API."""

from __future__ import annotations

from fastapi.testclient import TestClient


def _client_id(client: TestClient, csrf: str) -> str:
    response = client.post(
        "/api/clients",
        headers={"X-CSRF-Token": csrf},
        json={"name": "项目客户"},
    )
    assert response.status_code == 201
    return response.json()["data"]["id"]


def _create_engagement(client: TestClient, csrf: str, client_id: str, **extra):
    payload = {
        "client_id": client_id,
        "name": "年度风险评估",
        "engagement_type": "risk_assessment",
        "start_date": "2026-11-01",
        "end_date": "2026-12-31",
        "scope_summary": "总部与云环境",
    }
    payload.update(extra)
    return client.post("/api/engagements", headers={"X-CSRF-Token": csrf}, json=payload)


def test_create_engagement(client: TestClient, bootstrap_admin: dict) -> None:
    csrf = bootstrap_admin["csrf_token"]
    client_id = _client_id(client, csrf)
    response = _create_engagement(client, csrf, client_id)
    assert response.status_code == 201
    data = response.json()["data"]
    assert data["code"].startswith("ENG-")
    assert data["status"] == "draft"
    assert data["client_id"] == client_id
    assert data["client_name"] == "项目客户"


def test_engagement_requires_existing_client(client: TestClient, bootstrap_admin: dict) -> None:
    response = _create_engagement(client, bootstrap_admin["csrf_token"], "missing")
    assert response.status_code == 404


def test_end_before_start_is_rejected(client: TestClient, bootstrap_admin: dict) -> None:
    csrf = bootstrap_admin["csrf_token"]
    client_id = _client_id(client, csrf)
    response = _create_engagement(
        client, csrf, client_id, start_date="2026-12-31", end_date="2026-11-01"
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "AEG-2003"


def test_transition_chain_and_illegal_jump(client: TestClient, bootstrap_admin: dict) -> None:
    csrf = bootstrap_admin["csrf_token"]
    engagement = _create_engagement(client, csrf, _client_id(client, csrf)).json()["data"]

    def move(target: str):
        return client.post(
            f"/api/engagements/{engagement['id']}/transition",
            headers={"X-CSRF-Token": csrf},
            json={"status": target, "note": "推进"},
        )

    illegal = move("closed")
    assert illegal.status_code == 409
    assert illegal.json()["error"]["code"] == "AEG-4001"

    assert move("scoping").status_code == 200
    assert move("fieldwork").status_code == 200
    assert move("reporting").status_code == 200
    assert move("closed").status_code == 200


def test_update_engagement_fields(client: TestClient, bootstrap_admin: dict) -> None:
    csrf = bootstrap_admin["csrf_token"]
    engagement = _create_engagement(client, csrf, _client_id(client, csrf)).json()["data"]
    response = client.patch(
        f"/api/engagements/{engagement['id']}",
        headers={"X-CSRF-Token": csrf},
        json={"name": "更名后的项目", "objectives": "目标已更新"},
    )
    assert response.status_code == 200
    assert response.json()["data"]["name"] == "更名后的项目"


def test_stakeholder_crud(client: TestClient, bootstrap_admin: dict) -> None:
    csrf = bootstrap_admin["csrf_token"]
    engagement = _create_engagement(client, csrf, _client_id(client, csrf)).json()["data"]

    created = client.post(
        f"/api/engagements/{engagement['id']}/stakeholders",
        headers={"X-CSRF-Token": csrf},
        json={"name": "关键客户", "role_title": "CIO", "influence": "high", "interest": "high"},
    )
    assert created.status_code == 201
    stakeholder = created.json()["data"]

    listed = client.get(f"/api/engagements/{engagement['id']}/stakeholders").json()["data"]
    assert [item["name"] for item in listed] == ["关键客户"]

    updated = client.patch(
        f"/api/stakeholders/{stakeholder['id']}",
        headers={"X-CSRF-Token": csrf},
        json={"role_title": "首席信息官"},
    )
    assert updated.json()["data"]["role_title"] == "首席信息官"

    deleted = client.delete(
        f"/api/stakeholders/{stakeholder['id']}", headers={"X-CSRF-Token": csrf}
    )
    assert deleted.status_code == 200
    assert client.get(f"/api/engagements/{engagement['id']}/stakeholders").json()["data"] == []


def test_stakeholder_invalid_level(client: TestClient, bootstrap_admin: dict) -> None:
    csrf = bootstrap_admin["csrf_token"]
    engagement = _create_engagement(client, csrf, _client_id(client, csrf)).json()["data"]
    response = client.post(
        f"/api/engagements/{engagement['id']}/stakeholders",
        headers={"X-CSRF-Token": csrf},
        json={"name": "X", "influence": "extreme"},
    )
    assert response.status_code == 422
    assert response.json()["error"]["details"]["field"] == "influence"


def test_engagement_filters(client: TestClient, bootstrap_admin: dict) -> None:
    csrf = bootstrap_admin["csrf_token"]
    engagement = _create_engagement(client, csrf, _client_id(client, csrf)).json()["data"]
    client.post(
        f"/api/engagements/{engagement['id']}/transition",
        headers={"X-CSRF-Token": csrf},
        json={"status": "scoping"},
    )
    assert len(client.get("/api/engagements", params={"status": "scoping"}).json()["data"]) == 1
    assert len(client.get("/api/engagements", params={"status": "draft"}).json()["data"]) == 0
    assert len(
        client.get("/api/engagements", params={"q": "年度风险"}).json()["data"]
    ) == 1


def test_dashboard_summary(client: TestClient, bootstrap_admin: dict) -> None:
    csrf = bootstrap_admin["csrf_token"]
    _create_engagement(client, csrf, _client_id(client, csrf))
    summary = client.get("/api/dashboard/summary").json()["data"]
    assert summary["clients"]["total"] == 1
    assert summary["engagements"]["total"] == 1
    assert summary["recent_events"]
