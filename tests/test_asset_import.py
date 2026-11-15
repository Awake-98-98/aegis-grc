"""CSV import: encodings, header aliases, duplicates and per-row errors."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

HEADER = (
    "name,asset_type,category,owner,department,location,"
    "confidentiality,integrity,availability,lifecycle_status,description"
)


@pytest.fixture()
def engagement_id(client: TestClient, admin_headers: dict) -> str:
    client.post("/api/clients", json={"name": "丙客户"}, headers=admin_headers)
    client_row = client.get("/api/clients").json()["data"][0]
    return client.post(
        "/api/engagements",
        json={"client_id": client_row["id"], "name": "导入测试项目"},
        headers=admin_headers,
    ).json()["data"]["id"]


def _upload(
    client: TestClient, headers: dict, engagement_id: str, payload: bytes, name: str = "assets.csv"
):
    return client.post(
        f"/api/engagements/{engagement_id}/assets/import",
        files={"file": (name, payload, "text/csv")},
        headers=headers,
    )


def test_import_creates_assets(client: TestClient, admin_headers: dict, engagement_id: str) -> None:
    rows = [
        "订单服务,business,application,王工,信息中心,核心机房,3,3,4,active,交易主链路",
        "备份存储,supporting,server,李工,信息中心,灾备机房,2,3,3,active,",
    ]
    payload = (HEADER + "\n" + "\n".join(rows) + "\n").encode("utf-8")

    response = _upload(client, admin_headers, engagement_id, payload)
    assert response.status_code == 200, response.text
    result = response.json()["data"]
    assert result["imported"] == 2
    assert result["skipped"] == 0
    assert result["failed"] == 0
    assert result["codes"] == ["AST-0001", "AST-0002"]

    listed = client.get(f"/api/engagements/{engagement_id}/assets").json()
    assert listed["meta"]["total"] == 2
    order = {row["name"]: row for row in listed["data"]}
    assert order["订单服务"]["criticality"] == "critical"
    assert order["订单服务"]["description"] == "交易主链路"


def test_import_skips_existing_names(
    client: TestClient, admin_headers: dict, engagement_id: str
) -> None:
    payload = (HEADER + "\n订单服务,business,application,,,,3,3,3,active,\n").encode("utf-8")
    assert _upload(client, admin_headers, engagement_id, payload).json()["data"]["imported"] == 1

    again = _upload(client, admin_headers, engagement_id, payload).json()["data"]
    assert again["imported"] == 0
    assert again["skipped"] == 1
    assert again["skipped_rows"][0]["name"] == "订单服务"
    assert client.get(f"/api/engagements/{engagement_id}/assets").json()["meta"]["total"] == 1


def test_import_after_delete_reuses_free_codes(
    client: TestClient, admin_headers: dict, engagement_id: str
) -> None:
    """Deleting an asset leaves a gap; a later import must not clash with it."""
    for index in (1, 2, 3):
        created = client.post(
            f"/api/engagements/{engagement_id}/assets",
            json={"name": f"既有资产{index}"},
            headers=admin_headers,
        )
        assert created.status_code == 201, created.text
    second = client.get(f"/api/engagements/{engagement_id}/assets").json()["data"][1]
    assert client.delete(f"/api/assets/{second['id']}", headers=admin_headers).status_code == 200

    payload = (
        HEADER + "\n新资产A,business,application,,,,2,2,2,active,\n"
        "新资产B,business,application,,,,2,2,2,active,\n"
    ).encode("utf-8")
    response = _upload(client, admin_headers, engagement_id, payload)
    assert response.status_code == 200, response.text
    result = response.json()["data"]
    assert result["imported"] == 2
    assert result["codes"] == ["AST-0004", "AST-0005"]


def test_import_accepts_chinese_headers_and_values(
    client: TestClient, admin_headers: dict, engagement_id: str
) -> None:
    payload = "资产名称,类型,类别,责任人,机密性,完整性,可用性,状态\n核心数据库,业务资产,数据库,张工,4,3,3,在用\n".encode(
        "utf-8"
    )
    result = _upload(client, admin_headers, engagement_id, payload).json()["data"]
    assert result["imported"] == 1

    asset = client.get(f"/api/engagements/{engagement_id}/assets").json()["data"][0]
    assert asset["name"] == "核心数据库"
    assert asset["asset_type"] == "business"
    assert asset["category"] == "database"
    assert asset["lifecycle_status"] == "active"
    assert asset["confidentiality"] == 4


def test_import_reads_gb18030_files(
    client: TestClient, admin_headers: dict, engagement_id: str
) -> None:
    payload = (HEADER + "\n财务系统,business,application,,,,3,3,3,active,\n").encode("gb18030")
    result = _upload(client, admin_headers, engagement_id, payload).json()["data"]
    assert result["imported"] == 1


def test_import_reports_bad_rows_and_keeps_good_ones(
    client: TestClient, admin_headers: dict, engagement_id: str
) -> None:
    rows = [
        "正常资产,business,application,,,,2,2,2,active,",
        "越界资产,business,application,,,,9,2,2,active,",
        "未知类型资产,飞艇,application,,,,2,2,2,active,",
        ",business,application,,,,2,2,2,active,",
    ]
    payload = (HEADER + "\n" + "\n".join(rows) + "\n").encode("utf-8")

    result = _upload(client, admin_headers, engagement_id, payload).json()["data"]
    assert result["imported"] == 1
    assert result["failed"] == 3
    by_row = {item["row"]: item for item in result["errors"]}
    assert by_row[3]["field"] == "confidentiality"
    assert by_row[4]["field"] == "asset_type"
    assert by_row[5]["field"] == "name"


def test_import_requires_name_column(
    client: TestClient, admin_headers: dict, engagement_id: str
) -> None:
    payload = "owner,category\n王工,application\n".encode("utf-8")
    response = _upload(client, admin_headers, engagement_id, payload)
    assert response.status_code == 422
    body = response.json()["error"]
    assert body["code"] == "AEG-2003"
    assert body["details"]["missing"] == ["name"]


def test_import_rejects_empty_file(
    client: TestClient, admin_headers: dict, engagement_id: str
) -> None:
    response = _upload(client, admin_headers, engagement_id, b"")
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "AEG-2003"


def test_template_download_has_header(
    client: TestClient, admin_headers: dict
) -> None:
    response = client.get("/api/assets/template.csv")
    assert response.status_code == 200
    assert response.text.lstrip("\ufeff").startswith("name,asset_type,category")
    assert "订单服务" in response.text
