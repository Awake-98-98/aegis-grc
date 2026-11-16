"""Risk assessment console pages."""

from __future__ import annotations

from fastapi.testclient import TestClient


def _setup(client: TestClient, admin: dict) -> tuple[dict, dict]:
    client.post("/api/clients", json={"name": "评估客户"}, headers=admin)
    client_row = client.get("/api/clients").json()["data"][0]
    engagement = client.post(
        "/api/engagements",
        json={"client_id": client_row["id"], "name": "评估项目"},
        headers=admin,
    ).json()["data"]
    asset = client.post(
        f"/api/engagements/{engagement['id']}/assets",
        json={"name": "核心数据库", "category": "database"},
        headers=admin,
    ).json()["data"]
    threat = client.post(
        f"/api/engagements/{engagement['id']}/threats",
        json={"name": "勒索软件", "category": "malicious"},
        headers=admin,
    ).json()["data"]
    link = client.post(
        f"/api/assets/{asset['id']}/threats",
        json={"threat_id": threat["id"], "vulnerability": "备份未离线"},
        headers=admin,
    ).json()["data"]
    return engagement, link


def _assessment(client: TestClient, admin: dict, engagement_id: str) -> dict:
    return client.post(
        f"/api/engagements/{engagement_id}/assessments",
        json={"title": "首轮评估", "assessor": "顾问甲"},
        headers=admin,
    ).json()["data"]


def _add_risk(client: TestClient, admin: dict, assessment_id: str, link_id: str) -> dict:
    return client.post(
        f"/api/assessments/{assessment_id}/risks",
        json={
            "asset_threat_id": link_id,
            "likelihood": 4,
            "impact": 5,
            "residual_likelihood": 2,
            "residual_impact": 3,
        },
        headers=admin,
    ).json()["data"]


def test_assessment_list_and_create(
    client: TestClient, bootstrap_admin: dict
) -> None:
    headers = {"X-CSRF-Token": bootstrap_admin["csrf_token"]}
    csrf = bootstrap_admin["csrf_token"]
    engagement, _ = _setup(client, headers)

    listing = client.get(f"/engagements/{engagement['id']}/assessments")
    assert listing.status_code == 200
    assert "风险评估" in listing.text
    assert "尚无评估批次" in listing.text

    created = client.post(
        f"/engagements/{engagement['id']}/assessments",
        data={
            "csrf_token": csrf,
            "title": "网页首轮评估",
            "assessor": "顾问乙",
            "summary": "覆盖核心系统",
        },
    )
    assert created.status_code == 303
    detail_url = created.headers["location"]
    detail = client.get(detail_url)
    assert detail.status_code == 200
    assert "固有风险矩阵" in detail.text
    assert "网页首轮评估" in detail.text
    assert "尚未评分" in detail.text


def test_score_risk_through_form(client: TestClient, bootstrap_admin: dict) -> None:
    headers = {"X-CSRF-Token": bootstrap_admin["csrf_token"]}
    csrf = bootstrap_admin["csrf_token"]
    engagement, link = _setup(client, headers)
    assessment = _assessment(client, headers, engagement["id"])

    form = client.get(f"/assessments/{assessment['id']}/risks/new")
    assert form.status_code == 200
    assert "核心数据库" in form.text
    assert "勒索软件" in form.text

    submitted = client.post(
        f"/assessments/{assessment['id']}/risks",
        data={
            "csrf_token": csrf,
            "asset_threat_id": link["id"],
            "likelihood": "4",
            "impact": "5",
            "residual_likelihood": "2",
            "residual_impact": "3",
            "treatment": "mitigate",
            "rationale": "上线异地备份",
        },
    )
    assert submitted.status_code == 303
    detail = client.get(f"/assessments/{assessment['id']}")
    assert "核心数据库" in detail.text
    assert "20" in detail.text
    assert "缓解" in detail.text
    assert "可接受" in detail.text


def test_edit_and_delete_risk_pages(client: TestClient, bootstrap_admin: dict) -> None:
    headers = {"X-CSRF-Token": bootstrap_admin["csrf_token"]}
    csrf = bootstrap_admin["csrf_token"]
    engagement, link = _setup(client, headers)
    assessment = _assessment(client, headers, engagement["id"])
    item = _add_risk(client, headers, assessment["id"], link["id"])

    edit = client.get(f"/risks/{item['id']}/edit")
    assert edit.status_code == 200
    assert "编辑评分" in edit.text

    updated = client.post(
        f"/risks/{item['id']}/edit",
        data={
            "csrf_token": csrf,
            "likelihood": "3",
            "impact": "3",
            "residual_likelihood": "2",
            "residual_impact": "2",
            "treatment": "accept",
            "rationale": "客户接受残余风险",
        },
    )
    assert updated.status_code == 303
    detail = client.get(f"/assessments/{assessment['id']}")
    assert "客户接受残余风险" in detail.text

    deleted = client.post(
        f"/risks/{item['id']}/delete", data={"csrf_token": csrf}
    )
    assert deleted.status_code == 303
    assert "尚未评分" in client.get(f"/assessments/{assessment['id']}").text


def test_issue_freezes_console(client: TestClient, bootstrap_admin: dict) -> None:
    headers = {"X-CSRF-Token": bootstrap_admin["csrf_token"]}
    csrf = bootstrap_admin["csrf_token"]
    engagement, link = _setup(client, headers)
    assessment = _assessment(client, headers, engagement["id"])
    _add_risk(client, headers, assessment["id"], link["id"])

    issued = client.post(
        f"/assessments/{assessment['id']}/issue", data={"csrf_token": csrf}
    )
    assert issued.status_code == 303
    detail = client.get(f"/assessments/{assessment['id']}")
    assert "已签发" in detail.text
    assert "签发批次" not in detail.text
    assert "新增评分" not in detail.text


def test_compare_page(client: TestClient, bootstrap_admin: dict) -> None:
    headers = {"X-CSRF-Token": bootstrap_admin["csrf_token"]}
    engagement, link = _setup(client, headers)
    baseline = _assessment(client, headers, engagement["id"])
    _add_risk(client, headers, baseline["id"], link["id"])
    client.post(f"/api/assessments/{baseline['id']}/issue", headers=headers)

    current = _assessment(client, headers, engagement["id"])
    _add_risk(client, headers, current["id"], link["id"])

    prompt = client.get(f"/assessments/{current['id']}/compare")
    assert prompt.status_code == 200
    assert "选择一个基线批次" in prompt.text

    result = client.get(
        f"/assessments/{current['id']}/compare",
        params={"against": baseline["id"]},
    )
    assert result.status_code == 200
    assert "逐项对比" in result.text
    assert "未变" in result.text
    assert "RA-0001" in result.text


def test_appetite_form(client: TestClient, bootstrap_admin: dict) -> None:
    headers = {"X-CSRF-Token": bootstrap_admin["csrf_token"]}
    csrf = bootstrap_admin["csrf_token"]
    engagement, _ = _setup(client, headers)

    response = client.post(
        f"/engagements/{engagement['id']}/risk-appetite",
        data={
            "csrf_token": csrf,
            "max_acceptable_score": "12",
            "statement": "残余分值不超过 12",
        },
    )
    assert response.status_code == 303
    listing = client.get(f"/engagements/{engagement['id']}/assessments")
    assert "当前可接受的最高残余分值：12" in listing.text
    assert "残余分值不超过 12" in listing.text
