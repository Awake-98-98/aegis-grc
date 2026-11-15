"""Web console pages for the asset inventory."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def project(client: TestClient, admin_headers: dict) -> dict:
    client.post("/api/clients", json={"name": "网页资产客户"}, headers=admin_headers)
    client_row = client.get("/api/clients").json()["data"][0]
    engagement = client.post(
        "/api/engagements",
        json={"client_id": client_row["id"], "name": "网页资产项目"},
        headers=admin_headers,
    ).json()["data"]
    return engagement


def test_asset_pages_render(
    client: TestClient, bootstrap_admin: dict, project: dict
) -> None:
    listing = client.get(f"/engagements/{project['id']}/assets")
    assert listing.status_code == 200
    assert "资产清单" in listing.text
    assert "批量导入" in listing.text

    form = client.get(f"/engagements/{project['id']}/assets/new")
    assert form.status_code == 200
    assert "登记资产" in form.text


def test_asset_web_create_and_detail(
    client: TestClient, bootstrap_admin: dict, project: dict
) -> None:
    csrf = bootstrap_admin["csrf_token"]
    created = client.post(
        f"/engagements/{project['id']}/assets",
        data={
            "csrf_token": csrf,
            "name": "网页订单服务",
            "asset_type": "business",
            "category": "application",
            "owner": "王工",
            "department": "信息中心",
            "location": "核心机房",
            "confidentiality": "3",
            "integrity": "3",
            "availability": "4",
            "lifecycle_status": "active",
            "description": "网页表单创建",
        },
    )
    assert created.status_code == 303, created.text
    detail_url = created.headers["location"]

    detail = client.get(detail_url)
    assert detail.status_code == 200
    assert "网页订单服务" in detail.text
    assert "AST-0001" in detail.text
    assert "关键" in detail.text
    assert "威胁面" in detail.text

    listing = client.get(f"/engagements/{project['id']}/assets")
    assert "网页订单服务" in listing.text

    engagement_page = client.get(f"/engagements/{project['id']}")
    assert "资产清单" in engagement_page.text


def test_asset_web_edit(
    client: TestClient, bootstrap_admin: dict, project: dict
) -> None:
    csrf = bootstrap_admin["csrf_token"]
    created = client.post(
        f"/engagements/{project['id']}/assets",
        data={"csrf_token": csrf, "name": "待改名资产"},
    )
    asset_id = created.headers["location"].rsplit("/", 1)[-1]

    form = client.get(f"/assets/{asset_id}/edit")
    assert form.status_code == 200
    assert "待改名资产" in form.text

    updated = client.post(
        f"/assets/{asset_id}/edit",
        data={
            "csrf_token": csrf,
            "name": "已改名资产",
            "asset_type": "supporting",
            "category": "server",
            "confidentiality": "4",
            "integrity": "2",
            "availability": "2",
            "lifecycle_status": "active",
        },
    )
    assert updated.status_code == 303
    assert "已改名资产" in client.get(f"/assets/{asset_id}").text


def test_asset_web_link_threat(
    client: TestClient, bootstrap_admin: dict, project: dict
) -> None:
    csrf = bootstrap_admin["csrf_token"]
    asset_id = client.post(
        f"/engagements/{project['id']}/assets",
        data={"csrf_token": csrf, "name": "关联测试资产"},
    ).headers["location"].rsplit("/", 1)[-1]
    threat = client.post(
        f"/api/engagements/{project['id']}/threats",
        json={"name": "网页威胁"},
        headers={"X-CSRF-Token": csrf},
    ).json()["data"]

    linked = client.post(
        f"/assets/{asset_id}/threats",
        data={
            "csrf_token": csrf,
            "threat_id": threat["id"],
            "exposure": "high",
            "vulnerability": "未打补丁",
        },
    )
    assert linked.status_code == 303
    detail = client.get(f"/assets/{asset_id}")
    assert "网页威胁" in detail.text
    assert "未打补丁" in detail.text


def test_asset_web_import(
    client: TestClient, bootstrap_admin: dict, project: dict
) -> None:
    csrf = bootstrap_admin["csrf_token"]
    csv_body = (
        "name,category,confidentiality,integrity,availability\n"
        "网页导入资产,application,3,3,3\n"
    ).encode("utf-8")

    response = client.post(
        f"/engagements/{project['id']}/assets/import",
        data={"csrf_token": csrf},
        files={"file": ("assets.csv", csv_body, "text/csv")},
    )
    assert response.status_code == 303
    assert "网页导入资产" in client.get(f"/engagements/{project['id']}/assets").text


def test_asset_web_delete(
    client: TestClient, bootstrap_admin: dict, project: dict
) -> None:
    csrf = bootstrap_admin["csrf_token"]
    asset_id = client.post(
        f"/engagements/{project['id']}/assets",
        data={"csrf_token": csrf, "name": "网页待删资产"},
    ).headers["location"].rsplit("/", 1)[-1]

    removed = client.post(f"/assets/{asset_id}/delete", data={"csrf_token": csrf})
    assert removed.status_code == 303
    assert client.get(f"/assets/{asset_id}").status_code == 404
    assert "网页待删资产" not in client.get(f"/engagements/{project['id']}/assets").text
