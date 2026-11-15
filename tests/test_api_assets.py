"""Asset API tests: numbering, CIA grading, filtering and audit trail."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def engagement_id(client: TestClient, admin_headers: dict) -> str:
    client.post("/api/clients", json={"name": "甲客户"}, headers=admin_headers)
    clients = client.get("/api/clients").json()["data"]
    created = client.post(
        "/api/engagements",
        json={"client_id": clients[0]["id"], "name": "年度风险评估"},
        headers=admin_headers,
    )
    assert created.status_code == 201, created.text
    return created.json()["data"]["id"]


def test_create_asset_assigns_sequential_codes(
    client: TestClient, admin_headers: dict, engagement_id: str
) -> None:
    first = client.post(
        f"/api/engagements/{engagement_id}/assets",
        json={"name": "订单服务", "category": "application", "asset_type": "business"},
        headers=admin_headers,
    )
    second = client.post(
        f"/api/engagements/{engagement_id}/assets",
        json={"name": "备份存储", "category": "server"},
        headers=admin_headers,
    )
    assert first.status_code == 201, first.text
    assert second.status_code == 201, second.text
    assert first.json()["data"]["code"] == "AST-0001"
    assert second.json()["data"]["code"] == "AST-0002"


def test_duplicate_asset_name_is_rejected(
    client: TestClient, admin_headers: dict, engagement_id: str
) -> None:
    payload = {"name": "核心数据库"}
    assert (
        client.post(
            f"/api/engagements/{engagement_id}/assets", json=payload, headers=admin_headers
        ).status_code
        == 201
    )
    duplicate = client.post(
        f"/api/engagements/{engagement_id}/assets", json=payload, headers=admin_headers
    )
    assert duplicate.status_code == 409
    assert duplicate.json()["error"]["code"] == "AEG-2002"


def test_cia_grade_outside_range_is_rejected(
    client: TestClient, admin_headers: dict, engagement_id: str
) -> None:
    response = client.post(
        f"/api/engagements/{engagement_id}/assets",
        json={"name": "越界资产", "confidentiality": 5},
        headers=admin_headers,
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "AEG-2003"


def test_criticality_follows_the_highest_grade(
    client: TestClient, admin_headers: dict, engagement_id: str
) -> None:
    critical = client.post(
        f"/api/engagements/{engagement_id}/assets",
        json={"name": "财务库", "confidentiality": 4, "integrity": 2, "availability": 2},
        headers=admin_headers,
    ).json()["data"]
    low = client.post(
        f"/api/engagements/{engagement_id}/assets",
        json={"name": "打印服务器", "confidentiality": 1, "integrity": 1, "availability": 1},
        headers=admin_headers,
    ).json()["data"]

    assert critical["criticality"] == "critical"
    assert critical["priority_score"] == 20
    assert low["criticality"] == "low"
    assert low["priority_score"] == 7


def test_list_assets_sorts_by_priority_and_filters(
    client: TestClient, admin_headers: dict, engagement_id: str
) -> None:
    for name, grade in (("低价值", 1), ("中价值", 2), ("高价值", 4)):
        client.post(
            f"/api/engagements/{engagement_id}/assets",
            json={"name": name, "confidentiality": grade, "category": "data"},
            headers=admin_headers,
        )

    listing = client.get(f"/api/engagements/{engagement_id}/assets").json()
    assert [row["name"] for row in listing["data"]][0] == "高价值"
    assert listing["meta"]["total"] == 3

    only_critical = client.get(
        f"/api/engagements/{engagement_id}/assets?criticality=critical"
    ).json()
    assert only_critical["meta"]["total"] == 1
    assert only_critical["data"][0]["name"] == "高价值"

    searched = client.get(f"/api/engagements/{engagement_id}/assets?q=中价值").json()
    assert searched["meta"]["total"] == 1


def test_update_asset_writes_before_and_after_snapshot(
    client: TestClient, admin_headers: dict, engagement_id: str
) -> None:
    asset = client.post(
        f"/api/engagements/{engagement_id}/assets",
        json={"name": "旧名称", "confidentiality": 2},
        headers=admin_headers,
    ).json()["data"]

    updated = client.patch(
        f"/api/assets/{asset['id']}",
        json={"name": "新名称", "confidentiality": 4},
        headers=admin_headers,
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["data"]["criticality"] == "critical"

    events = client.get("/api/audit?entity_type=asset").json()["data"]
    update_event = next(row for row in events if row["action"] == "asset.update")
    assert update_event["detail"]["before"]["name"] == "旧名称"
    assert update_event["detail"]["after"]["name"] == "新名称"
    assert update_event["detail"]["after"]["confidentiality"] == 4


def test_delete_asset_removes_links(
    client: TestClient, admin_headers: dict, engagement_id: str
) -> None:
    asset = client.post(
        f"/api/engagements/{engagement_id}/assets",
        json={"name": "待删资产"},
        headers=admin_headers,
    ).json()["data"]
    threat = client.post(
        f"/api/engagements/{engagement_id}/threats",
        json={"name": "勒索软件"},
        headers=admin_headers,
    ).json()["data"]
    client.post(
        f"/api/assets/{asset['id']}/threats",
        json={"threat_id": threat["id"]},
        headers=admin_headers,
    )

    assert (
        client.delete(f"/api/assets/{asset['id']}", headers=admin_headers).status_code == 200
    )
    assert client.get(f"/api/assets/{asset['id']}").status_code == 404
    assert client.get(f"/api/assets/{asset['id']}/threats").status_code == 404


def test_summary_counts_by_criticality(
    client: TestClient, admin_headers: dict, engagement_id: str
) -> None:
    client.post(
        f"/api/engagements/{engagement_id}/assets",
        json={"name": "甲", "confidentiality": 4},
        headers=admin_headers,
    )
    client.post(
        f"/api/engagements/{engagement_id}/assets",
        json={"name": "乙", "integrity": 3},
        headers=admin_headers,
    )
    client.post(
        f"/api/engagements/{engagement_id}/assets",
        json={"name": "丙"},
        headers=admin_headers,
    )

    summary = client.get(f"/api/engagements/{engagement_id}/assets/summary").json()["data"]
    assert summary["total"] == 3
    assert summary["by_criticality"]["critical"] == 1
    assert summary["by_criticality"]["high"] == 1
    assert summary["by_criticality"]["medium"] == 1
    assert summary["unlinked"] == 3
