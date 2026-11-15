"""Threat catalog and asset-threat link tests."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def project(client: TestClient, admin_headers: dict) -> dict:
    client.post("/api/clients", json={"name": "乙客户"}, headers=admin_headers)
    client_row = client.get("/api/clients").json()["data"][0]
    engagement = client.post(
        "/api/engagements",
        json={"client_id": client_row["id"], "name": "数据安全评估"},
        headers=admin_headers,
    ).json()["data"]
    return {"client_id": client_row["id"], "id": engagement["id"]}


def test_create_threat_numbers_entries(
    client: TestClient, admin_headers: dict, project: dict
) -> None:
    first = client.post(
        f"/api/engagements/{project['id']}/threats",
        json={"name": "勒索软件", "category": "malicious", "actor": "external"},
        headers=admin_headers,
    )
    second = client.post(
        f"/api/engagements/{project['id']}/threats",
        json={"name": "机房断电", "category": "environmental", "actor": "nature"},
        headers=admin_headers,
    )
    assert first.status_code == 201, first.text
    assert first.json()["data"]["code"] == "THR-0001"
    assert second.json()["data"]["code"] == "THR-0002"


def test_unknown_threat_category_is_rejected(
    client: TestClient, admin_headers: dict, project: dict
) -> None:
    response = client.post(
        f"/api/engagements/{project['id']}/threats",
        json={"name": "未知分类", "category": "cosmic_ray"},
        headers=admin_headers,
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "AEG-2003"


def test_link_threat_to_asset(
    client: TestClient, admin_headers: dict, project: dict
) -> None:
    asset = client.post(
        f"/api/engagements/{project['id']}/assets",
        json={"name": "订单服务", "confidentiality": 3},
        headers=admin_headers,
    ).json()["data"]
    threat = client.post(
        f"/api/engagements/{project['id']}/threats",
        json={"name": "注入攻击"},
        headers=admin_headers,
    ).json()["data"]

    link = client.post(
        f"/api/assets/{asset['id']}/threats",
        json={
            "threat_id": threat["id"],
            "vulnerability": "输入校验缺失",
            "exposure": "high",
        },
        headers=admin_headers,
    )
    assert link.status_code == 201, link.text
    payload = link.json()["data"]
    assert payload["threat_code"] == "THR-0001"
    assert payload["asset_name"] == "订单服务"
    assert payload["exposure"] == "high"

    detail = client.get(f"/api/assets/{asset['id']}").json()["data"]
    assert detail["threat_count"] == 1


def test_link_twice_is_rejected(
    client: TestClient, admin_headers: dict, project: dict
) -> None:
    asset = client.post(
        f"/api/engagements/{project['id']}/assets",
        json={"name": "资产甲"},
        headers=admin_headers,
    ).json()["data"]
    threat = client.post(
        f"/api/engagements/{project['id']}/threats",
        json={"name": "威胁甲"},
        headers=admin_headers,
    ).json()["data"]
    body = {"threat_id": threat["id"]}

    assert (
        client.post(
            f"/api/assets/{asset['id']}/threats", json=body, headers=admin_headers
        ).status_code
        == 201
    )
    duplicate = client.post(
        f"/api/assets/{asset['id']}/threats", json=body, headers=admin_headers
    )
    assert duplicate.status_code == 409
    assert duplicate.json()["error"]["code"] == "AEG-2002"


def test_link_across_engagements_is_rejected(
    client: TestClient, admin_headers: dict, project: dict
) -> None:
    other = client.post(
        "/api/engagements",
        json={"client_id": project["client_id"], "name": "另一个项目"},
        headers=admin_headers,
    ).json()["data"]
    asset = client.post(
        f"/api/engagements/{project['id']}/assets",
        json={"name": "本项目资产"},
        headers=admin_headers,
    ).json()["data"]
    foreign_threat = client.post(
        f"/api/engagements/{other['id']}/threats",
        json={"name": "外项目威胁"},
        headers=admin_headers,
    ).json()["data"]

    response = client.post(
        f"/api/assets/{asset['id']}/threats",
        json={"threat_id": foreign_threat["id"]},
        headers=admin_headers,
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "AEG-2003"


def test_update_link_and_unlink(
    client: TestClient, admin_headers: dict, project: dict
) -> None:
    asset = client.post(
        f"/api/engagements/{project['id']}/assets",
        json={"name": "资产乙"},
        headers=admin_headers,
    ).json()["data"]
    threat = client.post(
        f"/api/engagements/{project['id']}/threats",
        json={"name": "威胁乙"},
        headers=admin_headers,
    ).json()["data"]
    link = client.post(
        f"/api/assets/{asset['id']}/threats",
        json={"threat_id": threat["id"], "exposure": "low"},
        headers=admin_headers,
    ).json()["data"]

    updated = client.patch(
        f"/api/asset-threats/{link['id']}",
        json={"exposure": "critical", "notes": "复测确认"},
        headers=admin_headers,
    )
    assert updated.status_code == 422
    assert updated.json()["error"]["code"] == "AEG-2003"

    updated = client.patch(
        f"/api/asset-threats/{link['id']}",
        json={"exposure": "high", "notes": "复测确认"},
        headers=admin_headers,
    )
    assert updated.status_code == 200
    assert updated.json()["data"]["exposure"] == "high"
    assert updated.json()["data"]["notes"] == "复测确认"

    assert (
        client.delete(f"/api/asset-threats/{link['id']}", headers=admin_headers).status_code
        == 200
    )
    assert client.get(f"/api/assets/{asset['id']}/threats").json()["data"] == []


def test_deleting_threat_removes_links(
    client: TestClient, admin_headers: dict, project: dict
) -> None:
    asset = client.post(
        f"/api/engagements/{project['id']}/assets",
        json={"name": "资产丙"},
        headers=admin_headers,
    ).json()["data"]
    threat = client.post(
        f"/api/engagements/{project['id']}/threats",
        json={"name": "威胁丙"},
        headers=admin_headers,
    ).json()["data"]
    client.post(
        f"/api/assets/{asset['id']}/threats",
        json={"threat_id": threat["id"]},
        headers=admin_headers,
    )

    assert client.delete(f"/api/threats/{threat['id']}", headers=admin_headers).status_code == 200
    assert client.get(f"/api/assets/{asset['id']}/threats").json()["data"] == []
